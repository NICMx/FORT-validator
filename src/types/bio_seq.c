#include "types/bio_seq.h"

#include "alloc.h"
#include "log.h"

static BIO_METHOD *method;

struct bioseq_priv {
	BIO *prefix;
	BIO *suffix;
};

static int
bioseq_read(BIO *bio, char *data, int len)
{
	struct bioseq_priv *priv = BIO_get_data(bio);
	int res;

	if (priv->prefix != NULL) {
		res = BIO_read(priv->prefix, data, len);
		if (BIO_eof(priv->prefix) || res <= 0) {
			BIO_free_all(priv->prefix);
			priv->prefix = NULL;
			return res;
		}
		return res;
	}

	return BIO_read(priv->suffix, data, len);
}

static int
bioseq_destroy(BIO *bio)
{
	struct bioseq_priv *priv;

	if (bio == NULL)
		return 0;

	priv = BIO_get_data(bio);
	BIO_free(priv->prefix);
	BIO_free(priv->suffix);
	free(priv);

	BIO_set_data(bio, NULL);
	BIO_set_init(bio, 0);

	return 1;
}

int
bioseq_setup(void)
{
	int type;

	type = BIO_get_new_index();
	if (type == -1)
		return op_crypto_err("BIO_get_new_index() returned -1.");

	method = BIO_meth_new(type | BIO_TYPE_FILTER, "seq");
	if (method == NULL)
		return op_crypto_err("BIO_meth_new() returned NULL.");

	if (!BIO_meth_set_read(method, bioseq_read) ||
	    !BIO_meth_set_destroy(method, bioseq_destroy)) {
		BIO_meth_free(method);
		method = NULL;
		return op_crypto_err("BIO_meth_set_*() returned 0.");
	}

	return 0;
}

void
bioseq_teardown(void)
{
	BIO_meth_free(method);
}

BIO *
BIO_new_seq(BIO *prefix, BIO *suffix)
{
	BIO *bio;
	struct bioseq_priv *priv;

	if (prefix == NULL || suffix == NULL)
		return NULL;

	bio = BIO_new(method);
	if (bio == NULL)
		return NULL;

	priv = pmalloc(sizeof(struct bioseq_priv));
	priv->prefix = prefix;
	priv->suffix = suffix;

	BIO_set_data(bio, priv);
	BIO_set_init(bio, 1);
	return bio;
}
