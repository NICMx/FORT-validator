#include "object/router_key.h"

#include <string.h>
#include "log.h"

struct sk_info {
	unsigned char	*ski;
	/* SKI length its constant (see RK_SKI_LEN) */
	unsigned char	*spk;
	size_t		spk_len;
	unsigned int	references;
};

static int
uchar_create(unsigned char **result, size_t size)
{
	unsigned char *tmp;

	tmp = malloc(size + 1);
	if (tmp == NULL)
		return pr_enomem();

	*result = tmp;
	return 0;
}

int
router_key_init(struct router_key *key, unsigned char const *ski,
    uint32_t as, unsigned char const *spk, size_t spk_len)
{
	struct sk_info *sk;
	int error;

	sk = malloc(sizeof(struct sk_info));
	if (sk == NULL)
		return pr_enomem();

	error = uchar_create(&sk->ski, RK_SKI_LEN);
	if (error) {
		free(sk);
		return pr_enomem();
	}

	error = uchar_create(&sk->spk, spk_len);
	if (error) {
		free(sk->ski);
		free(sk);
		return pr_enomem();
	}

	memcpy(sk->ski, ski, RK_SKI_LEN);
	sk->ski[RK_SKI_LEN] = '\0';
	memcpy(sk->spk, spk, spk_len);
	sk->spk[spk_len] = '\0';
	sk->spk_len = spk_len;
	sk->references = 1;

	key->as = as;
	key->sk = sk;

	return 0;
}

void
router_key_cleanup(struct router_key *key)
{
	sk_info_refput(key->sk);
}

void
sk_info_refget(struct sk_info *sk)
{
	sk->references++;
}

void
sk_info_refput(struct sk_info *sk)
{
	sk->references--;
	if (sk->references == 0) {
		free(sk->ski);
		free(sk->spk);
		free(sk);
	}
}

unsigned char *
sk_info_get_ski(struct sk_info *sk)
{
	return sk->ski;
}

unsigned char *
sk_info_get_spk(struct sk_info *sk)
{
	return sk->spk;
}

size_t
sk_info_get_spk_len(struct sk_info *sk)
{
	return sk->spk_len;
}
