#ifndef CRYPTO_H_DEFINED
#define CRYPTO_H_DEFINED

#include <sys/types.h>
#include "libknet.h"

struct crypto_instance {
	int	model;
	void	*model_instance;
};

int crypto_authenticate_and_decrypt (
	struct crypto_instance *instance,
	unsigned char *buf,
	ssize_t *buf_len);

int crypto_encrypt_and_sign (
	struct crypto_instance *instance,
	const unsigned char *buf_in,
	const ssize_t buf_in_len,
	unsigned char *buf_out, 
	ssize_t *buf_out_len);

int crypto_init(
	knet_handle_t knet_h,
	struct knet_handle_crypto_cfg *knet_handle_crypto_cfg);

void crypto_fini(
	knet_handle_t knet_h);

#endif /* CRYPTO_H_DEFINED */
