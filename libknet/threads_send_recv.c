/*
 * Copyright (C) 2010-2012 Red Hat, Inc.  All rights reserved.
 *
 * Authors: Fabio M. Di Nitto <fabbione@kronosnet.org>
 *          Federico Simoncelli <fsimon@kronosnet.org>
 *
 * This software licensed under GPL-2.0+, LGPL-2.0+
 */

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <math.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netdb.h>

#include "crypto.h"
#include "host.h"
#include "link.h"
#include "logging.h"
#include "threads_common.h"
#include "threads_send_recv.h"

static void _dispatch_to_links(knet_handle_t knet_h, struct knet_host *dst_host, unsigned char *outbuf, ssize_t outlen)
{
	int link_idx;

	if (pthread_mutex_lock(&dst_host->active_links_mutex) != 0) {
		log_debug(knet_h, KNET_SUB_SEND_T, "Unable to get active links mutex");
		return;
	}

	for (link_idx = 0; link_idx < dst_host->active_link_entries; link_idx++) {
		if (sendto(dst_host->link[dst_host->active_links[link_idx]].listener_sock,
			   outbuf, outlen, MSG_DONTWAIT,
			   (struct sockaddr *) &dst_host->link[dst_host->active_links[link_idx]].dst_addr,
			   sizeof(struct sockaddr_storage)) < 0) {
			log_debug(knet_h, KNET_SUB_SEND_T, "Unable to send data packet to host %s (%u) link %s:%s (%u): %s",
				  dst_host->name, dst_host->host_id,
				  dst_host->link[dst_host->active_links[link_idx]].status.dst_ipaddr,
				  dst_host->link[dst_host->active_links[link_idx]].status.dst_port,
				  dst_host->link[dst_host->active_links[link_idx]].link_id,
				  strerror(errno));
		}

		if ((dst_host->link_handler_policy == KNET_LINK_POLICY_RR) &&
		    (dst_host->active_link_entries > 1)) {
			uint8_t cur_link_id = dst_host->active_links[0];

			memmove(&dst_host->active_links[0], &dst_host->active_links[1], KNET_MAX_LINK - 1);
			dst_host->active_links[dst_host->active_link_entries - 1] = cur_link_id;

			break;
		}
	}

	pthread_mutex_unlock(&dst_host->active_links_mutex);

	return;
}

static void _handle_send_to_links(knet_handle_t knet_h, int sockfd)
{
	ssize_t inlen = 0, len, outlen, frag_len;
	struct knet_host *dst_host;
	uint16_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	unsigned char *outbuf = (unsigned char *)knet_h->send_to_links_buf;
	struct knet_hostinfo *knet_hostinfo;
	struct iovec iov_in;
	unsigned int temp_data_mtu;

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_SEND_T, "Unable to get read lock");
		goto host_unlock;
	}

	memset(&iov_in, 0, sizeof(iov_in));
	iov_in.iov_base = (void *)knet_h->send_to_links_buf->khp_data_userdata;
	iov_in.iov_len = KNET_MAX_PACKET_SIZE;

	inlen = readv(sockfd, &iov_in, 1);

	if (inlen < 0) {
		log_err(knet_h, KNET_SUB_SEND_T, "Unrecoverable error: %s", strerror(errno));
		goto out_unlock;
	}

	if (inlen == 0) {
		log_err(knet_h, KNET_SUB_SEND_T, "Unrecoverable error! Got 0 bytes from socket!");
		/* TODO: disconnection, should never happen! */
		goto out_unlock;
	}

	if ((knet_h->enabled != 1) &&
	    (knet_h->send_to_links_buf->kh_type != KNET_HEADER_TYPE_HOST_INFO)) { /* data forward is disabled */
		log_debug(knet_h, KNET_SUB_SEND_T, "Received data packet but forwarding is disabled");
		goto out_unlock;
	}

	/*
	 * move this into a separate function to expand on
	 * extra switching rules
	 */
	switch(knet_h->send_to_links_buf->kh_type) {
		case KNET_HEADER_TYPE_DATA:
			if (knet_h->dst_host_filter_fn) {
				bcast = knet_h->dst_host_filter_fn(
						(const unsigned char *)knet_h->send_to_links_buf->khp_data_userdata,
						inlen,
						knet_h->send_to_links_buf->kh_node,
						dst_host_ids,
						&dst_host_ids_entries);
				if (bcast < 0) {
					log_debug(knet_h, KNET_SUB_SEND_T, "Error from dst_host_filter_fn: %d", bcast);
					goto out_unlock;
				}

				if ((!bcast) && (!dst_host_ids_entries)) {
					log_debug(knet_h, KNET_SUB_SEND_T, "Message is unicast but no dst_host_ids_entries");
					goto out_unlock;
				}
			}
			break;
		case KNET_HEADER_TYPE_HOST_INFO:
			knet_hostinfo = (struct knet_hostinfo *)knet_h->send_to_links_buf->khp_data_userdata;
			if (knet_hostinfo->khi_bcast == KNET_HOSTINFO_UCAST) {
				bcast = 0;
				dst_host_ids[0] = ntohs(knet_hostinfo->khi_dst_node_id);
				dst_host_ids_entries = 1;
			}
			break;
		default:
			log_warn(knet_h, KNET_SUB_SEND_T, "Receiving unknown messages from socket");
			goto out_unlock;
			break;
	}

	if (!knet_h->data_mtu) {
		/*
		 * using MIN_MTU_V4 for data mtu is not completely accurate but safe enough
		 */
		log_debug(knet_h, KNET_SUB_SEND_T,
			  "Received data packet but data MTU is still unknown."
			  " Packet might not be delivered."
			  " Assuming mininum IPv4 mtu (%d)",
			  KNET_PMTUD_MIN_MTU_V4);
		temp_data_mtu = KNET_PMTUD_MIN_MTU_V4;
	} else {
		/*
		 * take a copy of the mtu to avoid value changing under
		 * our feet while we are sending a fragmented pckt
		 */
		temp_data_mtu = knet_h->data_mtu;
	}

	frag_len = inlen;

	knet_h->send_to_links_buf->khp_data_frag_seq = 0;
	knet_h->send_to_links_buf->khp_data_frag_num = ceil((float)inlen / temp_data_mtu);

	if (knet_h->send_to_links_buf->khp_data_frag_num > 1) {
		log_debug(knet_h, KNET_SUB_SEND_T, "Current inlen: %zu data mtu: %u frags: %d",
			  inlen, temp_data_mtu, knet_h->send_to_links_buf->khp_data_frag_num);
	}

	if (!bcast) {
		int host_idx;

		while (knet_h->send_to_links_buf->khp_data_frag_seq < knet_h->send_to_links_buf->khp_data_frag_num) {

			knet_h->send_to_links_buf->khp_data_frag_seq++;

			if (frag_len > temp_data_mtu) {
				outlen = len = temp_data_mtu + KNET_HEADER_DATA_SIZE;
			} else {
				outlen = len = frag_len + KNET_HEADER_DATA_SIZE;
			}

			for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
				dst_host = knet_h->host_index[dst_host_ids[host_idx]];
				if (!dst_host) {
					log_debug(knet_h, KNET_SUB_SEND_T, "unicast packet, host not found");
					continue;
				}

				if (knet_h->send_to_links_buf->khp_data_frag_seq == 1) {
					knet_h->send_to_links_buf->khp_data_seq_num = htons(++dst_host->ucast_seq_num_tx);
				} else {
					knet_h->send_to_links_buf->khp_data_seq_num = htons(dst_host->ucast_seq_num_tx);
				}

				if (knet_h->crypto_instance) {
					if (crypto_encrypt_and_sign(knet_h,
							    (const unsigned char *)knet_h->send_to_links_buf,
							    len,
							    knet_h->send_to_links_buf_crypt,
							    &outlen) < 0) {
						log_debug(knet_h, KNET_SUB_SEND_T, "Unable to encrypt unicast packet");
						goto out_unlock;
					}
					outbuf = knet_h->send_to_links_buf_crypt;
				}

				_dispatch_to_links(knet_h, dst_host, outbuf, outlen);

			}

			if (frag_len > temp_data_mtu) {
				frag_len = frag_len - temp_data_mtu;
				memmove(knet_h->send_to_links_buf->khp_data_userdata,
					knet_h->send_to_links_buf->khp_data_userdata + temp_data_mtu,
					frag_len);
			}
		}
	} else {
		knet_h->send_to_links_buf->khp_data_seq_num = htons(++knet_h->bcast_seq_num_tx);

		while (knet_h->send_to_links_buf->khp_data_frag_seq < knet_h->send_to_links_buf->khp_data_frag_num) {

			knet_h->send_to_links_buf->khp_data_frag_seq++;

			if (frag_len > temp_data_mtu) {
				outlen = len = temp_data_mtu + KNET_HEADER_DATA_SIZE;
			} else {
				outlen = len = frag_len + KNET_HEADER_DATA_SIZE;
			}

			if (knet_h->crypto_instance) {
				if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->send_to_links_buf,
						    len,
						    knet_h->send_to_links_buf_crypt,
						    &outlen) < 0) {
					log_debug(knet_h, KNET_SUB_SEND_T, "Unable to encrypt mcast/bcast packet");
					goto out_unlock;
				}
				outbuf = knet_h->send_to_links_buf_crypt;
			}

			for (dst_host = knet_h->host_head; dst_host != NULL; dst_host = dst_host->next) {
				_dispatch_to_links(knet_h, dst_host, outbuf, outlen);
			}

			if (frag_len > temp_data_mtu) {
				frag_len = frag_len - temp_data_mtu;
				memmove(knet_h->send_to_links_buf->khp_data_userdata,
					knet_h->send_to_links_buf->khp_data_userdata + temp_data_mtu,
					frag_len);
			}
		}
	}

out_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);

host_unlock:
	if ((inlen > 0) && (knet_h->send_to_links_buf->kh_type == KNET_HEADER_TYPE_HOST_INFO)) {
		if (pthread_mutex_lock(&knet_h->host_mutex) != 0)
			log_debug(knet_h, KNET_SUB_SEND_T, "Unable to get mutex lock");
		pthread_cond_signal(&knet_h->host_cond);
		pthread_mutex_unlock(&knet_h->host_mutex);
	}
}

static int pckt_defrag(knet_handle_t knet_h, ssize_t *len)
{
	struct knet_host_defrag_buf *defrag_buf;

	/*
	 * this will need to be dynamic and we will need an all buffer full reclaim mechanism
	 * add here checks that we are handling a pckt from the same seq num
	 */

	defrag_buf = &knet_h->host_index[knet_h->recv_from_links_buf->kh_node]->defrag_buf[0];

	/*
	 * if the buf is not is use, then make sure it's clean
	 */
	if (!defrag_buf->in_use) {
		memset(defrag_buf, 0, sizeof(struct knet_host_defrag_buf));
		defrag_buf->in_use = 1;
		defrag_buf->pckt_seq = knet_h->recv_from_links_buf->khp_data_seq_num;
	}

	/*
	 * check if we already received this fragment
	 */
	if (defrag_buf->frag_map[knet_h->recv_from_links_buf->khp_data_frag_seq]) {
		/*
		 * if we have received this fragment and we didn't clear the buffer
		 * it means that we don't have all fragments yet
		 */
		return 1;
	}

	/*
	 *  we need to handle the last packet with gloves due to its different size
	 */

	if (knet_h->recv_from_links_buf->khp_data_frag_seq == knet_h->recv_from_links_buf->khp_data_frag_num) {
		defrag_buf->last_frag_size = *len;

		/*
		 * in the event when the last packet arrives first,
		 * we still don't know the offset vs the other fragments (based on MTU),
		 * so we store the fragment at the end of the buffer where it's safe
		 * and take a copy of the len so that we can restore its offset later.
		 * remember we can't use the local MTU for this calculation because pMTU
		 * can be asymettric between the same hosts.
		 */
		if (!defrag_buf->frag_size) {
			defrag_buf->last_first = 1;
			memcpy(defrag_buf->buf + (KNET_MAX_PACKET_SIZE - *len),
			       knet_h->recv_from_links_buf->khp_data_userdata,
			       *len);
		}
	} else {
		defrag_buf->frag_size = *len;
	}

	memcpy(defrag_buf->buf + ((knet_h->recv_from_links_buf->khp_data_frag_seq - 1) * defrag_buf->frag_size),
	       knet_h->recv_from_links_buf->khp_data_userdata, *len);

	defrag_buf->frag_recv++;
	defrag_buf->frag_map[knet_h->recv_from_links_buf->khp_data_frag_seq] = 1;

	/*
	 * check if we received all the fragments
	 */
	if (defrag_buf->frag_recv == knet_h->recv_from_links_buf->khp_data_frag_num) {
		/*
		 * special case the last pckt
		 */

		if (defrag_buf->last_first) {
			memmove(defrag_buf->buf + ((knet_h->recv_from_links_buf->khp_data_frag_num - 1) * defrag_buf->frag_size),
			        defrag_buf->buf + (KNET_MAX_PACKET_SIZE - defrag_buf->last_frag_size),
				defrag_buf->last_frag_size);
		}

		/*
		 * recalculate packet lenght
		 */

		*len = ((knet_h->recv_from_links_buf->khp_data_frag_num - 1) * defrag_buf->frag_size) + defrag_buf->last_frag_size;

		/*
		 * copy the pckt back in the user data
		 */
		memcpy(knet_h->recv_from_links_buf->khp_data_userdata, defrag_buf->buf, *len);

		/*
		 * free this buffer
		 */
		defrag_buf->in_use = 0;
		return 0;
	}

	return 1;
}

static void _handle_recv_from_links(knet_handle_t knet_h, int sockfd)
{
	ssize_t len, outlen;
	struct sockaddr_storage address;
	socklen_t addrlen;
	struct knet_host *src_host;
	struct knet_link *src_link;
	unsigned long long latency_last;
	uint16_t dst_host_ids[KNET_MAX_HOST];
	size_t dst_host_ids_entries = 0;
	int bcast = 1;
	struct timespec recvtime;
	unsigned char *outbuf = (unsigned char *)knet_h->recv_from_links_buf;
	struct knet_hostinfo *knet_hostinfo;
	struct iovec iov_out[1];

	if (pthread_rwlock_rdlock(&knet_h->list_rwlock) != 0) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to get read lock");
		return;
	}

	addrlen = sizeof(struct sockaddr_storage);
	len = recvfrom(sockfd, knet_h->recv_from_links_buf, KNET_DATABUFSIZE,
		MSG_DONTWAIT, (struct sockaddr *) &address, &addrlen);

	if (knet_h->crypto_instance) {
		if (crypto_authenticate_and_decrypt(knet_h,
						    (unsigned char *)knet_h->recv_from_links_buf,
						    &len) < 0) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Unable to decrypt/auth packet");
			goto exit_unlock;
		}
	}

	if (len < (KNET_HEADER_SIZE + 1)) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Packet is too short");
		goto exit_unlock;
	}

	if (knet_h->recv_from_links_buf->kh_version != KNET_HEADER_VERSION) {
		log_debug(knet_h, KNET_SUB_LINK_T, "Packet version does not match");
		goto exit_unlock;
	}

	knet_h->recv_from_links_buf->kh_node = ntohs(knet_h->recv_from_links_buf->kh_node);
	src_host = knet_h->host_index[knet_h->recv_from_links_buf->kh_node];
	if (src_host == NULL) {  /* host not found */
		log_debug(knet_h, KNET_SUB_LINK_T, "Unable to find source host for this packet");
		goto exit_unlock;
	}

	src_link = NULL;

	if ((knet_h->recv_from_links_buf->kh_type & KNET_HEADER_TYPE_PMSK) != 0) {
		src_link = src_host->link +
				(knet_h->recv_from_links_buf->khp_ping_link % KNET_MAX_LINK);
		if (src_link->dynamic == KNET_LINK_DYNIP) {
			if (memcmp(&src_link->dst_addr, &address, sizeof(struct sockaddr_storage)) != 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "host: %u link: %u appears to have changed ip address",
					  src_host->host_id, src_link->link_id);
				memcpy(&src_link->dst_addr, &address, sizeof(struct sockaddr_storage));
				if (getnameinfo((const struct sockaddr *)&src_link->dst_addr, sizeof(struct sockaddr_storage),
						src_link->status.dst_ipaddr, KNET_MAX_HOST_LEN,
						src_link->status.dst_port, KNET_MAX_PORT_LEN,
						NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
					log_debug(knet_h, KNET_SUB_LINK_T, "Unable to resolve ???");
					snprintf(src_link->status.dst_ipaddr, KNET_MAX_HOST_LEN - 1, "Unknown!!!");
					snprintf(src_link->status.dst_port, KNET_MAX_PORT_LEN - 1, "??");
				}
			}
			src_link->status.dynconnected = 1;
		}
	}

	switch (knet_h->recv_from_links_buf->kh_type) {
	case KNET_HEADER_TYPE_DATA:
		if (knet_h->enabled != 1) /* data forward is disabled */
			break;

		knet_h->recv_from_links_buf->khp_data_seq_num = ntohs(knet_h->recv_from_links_buf->khp_data_seq_num);

		if (knet_h->recv_from_links_buf->khp_data_frag_num > 1) {
			/*
			 * len as received from the socket also includes extra stuff
			 * that the defrag code doesn't care about. So strip it
			 * here and readd only for repadding once we are done
			 * defragging
			 */
			len = len - KNET_HEADER_DATA_SIZE;
			if (pckt_defrag(knet_h, &len)) {
				goto exit_unlock;
			}
			len = len + KNET_HEADER_DATA_SIZE;
		}

		if (knet_h->dst_host_filter_fn) {
			int host_idx;
			int found = 0;

			bcast = knet_h->dst_host_filter_fn(
					(const unsigned char *)knet_h->recv_from_links_buf->khp_data_userdata,
					len,
					knet_h->recv_from_links_buf->kh_node,
					dst_host_ids,
					&dst_host_ids_entries);
			if (bcast < 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Error from dst_host_filter_fn: %d", bcast);
				goto exit_unlock;
			}

			if ((!bcast) && (!dst_host_ids_entries)) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Message is unicast but no dst_host_ids_entries");
				goto exit_unlock;
			}

			/* check if we are dst for this packet */
			if (!bcast) {
				for (host_idx = 0; host_idx < dst_host_ids_entries; host_idx++) {
					if (dst_host_ids[host_idx] == knet_h->host_id) {
						found = 1;
						break;
					}
				}
				if (!found) {
					log_debug(knet_h, KNET_SUB_LINK_T, "Packet is not for us");
					goto exit_unlock;
				}
			}
		}

		if (!_should_deliver(src_host, bcast, knet_h->recv_from_links_buf->khp_data_seq_num)) {
			if (src_host->link_handler_policy != KNET_LINK_POLICY_ACTIVE) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Packet has already been delivered");
			}
			goto exit_unlock;
		}

		memset(iov_out, 0, sizeof(iov_out));
		iov_out[0].iov_base = (void *) knet_h->recv_from_links_buf->khp_data_userdata;
		iov_out[0].iov_len = len - KNET_HEADER_DATA_SIZE;

		if (writev(knet_h->sockfd, iov_out, 1) == iov_out[0].iov_len) {
			_has_been_delivered(src_host, bcast, knet_h->recv_from_links_buf->khp_data_seq_num);
		} else {
			log_debug(knet_h, KNET_SUB_LINK_T, "Packet has not been delivered");
		}

		break;
	case KNET_HEADER_TYPE_PING:
		outlen = KNET_HEADER_PING_SIZE;
		knet_h->recv_from_links_buf->kh_type = KNET_HEADER_TYPE_PONG;
		knet_h->recv_from_links_buf->kh_node = htons(knet_h->host_id);

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->recv_from_links_buf,
						    len,
						    knet_h->recv_from_links_buf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Unable to encrypt pong packet");
				break;
			}
			outbuf = knet_h->recv_from_links_buf_crypt;
		}

		sendto(src_link->listener_sock, outbuf, outlen, MSG_DONTWAIT,
				(struct sockaddr *) &src_link->dst_addr,
				sizeof(struct sockaddr_storage));

		break;
	case KNET_HEADER_TYPE_PONG:
		clock_gettime(CLOCK_MONOTONIC, &src_link->status.pong_last);

		memcpy(&recvtime, &knet_h->recv_from_links_buf->khp_ping_time[0], sizeof(struct timespec));
		timespec_diff(recvtime,
				src_link->status.pong_last, &latency_last);

		src_link->status.latency =
			((src_link->status.latency * src_link->latency_exp) +
			((latency_last / 1000llu) *
				(src_link->latency_fix - src_link->latency_exp))) /
					src_link->latency_fix;

		if (src_link->status.latency < src_link->pong_timeout) {
			if (!src_link->status.connected) {
				if (src_link->received_pong >= src_link->pong_count) {
					log_info(knet_h, KNET_SUB_LINK, "host: %u link: %u is up",
						 src_host->host_id, src_link->link_id);
					_link_updown(knet_h, src_host->host_id, src_link->link_id, src_link->status.enabled, 1);
				} else {
					src_link->received_pong++;
					log_debug(knet_h, KNET_SUB_LINK, "host: %u link: %u received pong: %u",
						  src_host->host_id, src_link->link_id, src_link->received_pong);
				}
			}
		}

		break;
	case KNET_HEADER_TYPE_PMTUD:
		outlen = KNET_HEADER_PMTUD_SIZE;
		knet_h->recv_from_links_buf->kh_type = KNET_HEADER_TYPE_PMTUD_REPLY;
		knet_h->recv_from_links_buf->kh_node = htons(knet_h->host_id);

		if (knet_h->crypto_instance) {
			if (crypto_encrypt_and_sign(knet_h,
						    (const unsigned char *)knet_h->recv_from_links_buf,
						    len,
						    knet_h->recv_from_links_buf_crypt,
						    &outlen) < 0) {
				log_debug(knet_h, KNET_SUB_LINK_T, "Unable to encrypt PMTUd reply packet");
				break;
			}
			outbuf = knet_h->recv_from_links_buf_crypt;
		}

		sendto(src_link->listener_sock, outbuf, outlen, MSG_DONTWAIT,
				(struct sockaddr *) &src_link->dst_addr,
				sizeof(struct sockaddr_storage));

		break;
	case KNET_HEADER_TYPE_PMTUD_REPLY:
		if (pthread_mutex_lock(&knet_h->pmtud_mutex) != 0) {
			log_debug(knet_h, KNET_SUB_LINK_T, "Unable to get mutex lock");
			break;
		}
		src_link->last_recv_mtu = knet_h->recv_from_links_buf->khp_pmtud_size;
		pthread_cond_signal(&knet_h->pmtud_cond);
		pthread_mutex_unlock(&knet_h->pmtud_mutex);
		break;
	case KNET_HEADER_TYPE_HOST_INFO:
		/*
		 * TODO: check if we need to fix padding as we do for data packets.
		 *       we currently don't have any HOST_INFO big enough to frag data
		 */
		if (knet_h->recv_from_links_buf->khp_data_frag_num > 1) {
			if (pckt_defrag(knet_h, &len)) {
				goto exit_unlock;
			}
		}

		knet_hostinfo = (struct knet_hostinfo *)knet_h->recv_from_links_buf->khp_data_userdata;
		if (knet_hostinfo->khi_bcast == KNET_HOSTINFO_UCAST) {
			knet_hostinfo->khi_dst_node_id = ntohs(knet_hostinfo->khi_dst_node_id);
		}
		switch(knet_hostinfo->khi_type) {
			case KNET_HOSTINFO_TYPE_LINK_UP_DOWN:
				src_link = src_host->link +
					(knet_hostinfo->khip_link_status_link_id % KNET_MAX_LINK);
				/*
				 * basically if the node is coming back to life from a crash
				 * we should receive a host info where local previous status == remote current status
				 * and so we can detect that node is showing up again
				 * we need to clear cbuffers and notify the node of our status by resending our host info
				 */
				if ((src_link->remoteconnected == KNET_HOSTINFO_LINK_STATUS_UP) &&
				    (src_link->remoteconnected == knet_hostinfo->khip_link_status_status)) {
					src_link->host_info_up_sent = 0;
				}
				src_link->remoteconnected = knet_hostinfo->khip_link_status_status;
				if (src_link->remoteconnected == KNET_HOSTINFO_LINK_STATUS_DOWN) {
					/*
					 * if a host is disconnecting clean, we note that in donnotremoteupdate
					 * so that we don't send host info back immediately but we wait
					 * for the node to send an update when it's alive again
					 */
					src_link->host_info_up_sent = 0;
					src_link->donnotremoteupdate = 1;
				} else {
					src_link->donnotremoteupdate = 0;
				}
				log_debug(knet_h, KNET_SUB_LINK, "host message up/down. from host: %u link: %u remote connected: %u",
					  src_host->host_id,
					  src_link->link_id,
					  src_link->remoteconnected);
				if (_host_dstcache_update_async(knet_h, src_host)) {
					log_debug(knet_h, KNET_SUB_LINK,
						  "Unable to update switch cache for host: %u link: %u remote connected: %u)",
						  src_host->host_id,
						  src_link->link_id,
						  src_link->remoteconnected);
				}
				break;
			case KNET_HOSTINFO_TYPE_LINK_TABLE:
				break;
			default:
				log_warn(knet_h, KNET_SUB_LINK, "Receiving unknown host info message from host %u", src_host->host_id);
				break;
		}
		break;
	default:
		goto exit_unlock;
	}

 exit_unlock:
	pthread_rwlock_unlock(&knet_h->list_rwlock);
}

void *_handle_send_to_links_thread(void *data)
{
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];
	int i, nev;

	/* preparing data buffer */
	knet_h->send_to_links_buf->kh_version = KNET_HEADER_VERSION;
	knet_h->send_to_links_buf->kh_node = htons(knet_h->host_id);

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(knet_h->send_to_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			if (events[i].data.fd == knet_h->sockfd) {
				knet_h->send_to_links_buf->kh_type = KNET_HEADER_TYPE_DATA;
			} else {
				knet_h->send_to_links_buf->kh_type = KNET_HEADER_TYPE_HOST_INFO;
			}
			_handle_send_to_links(knet_h, events[i].data.fd);
		}
	}

	return NULL;

}

void *_handle_recv_from_links_thread(void *data)
{
	int i, nev;
	knet_handle_t knet_h = (knet_handle_t) data;
	struct epoll_event events[KNET_EPOLL_MAX_EVENTS];

	while (!knet_h->fini_in_progress) {
		nev = epoll_wait(knet_h->recv_from_links_epollfd, events, KNET_EPOLL_MAX_EVENTS, -1);

		for (i = 0; i < nev; i++) {
			_handle_recv_from_links(knet_h, events[i].data.fd);
		}
	}

	return NULL;
}