#include "config.h"

static struct rpki_config config;

void
config_set(struct rpki_config *new)
{
	config = *new;
}

char const *
config_get_tal(void)
{
	return config.tal;
}

char const *
config_get_local_repository(void)
{
	return config.local_repository;
}

bool
config_get_disable_rsync(void)
{
	return config.disable_rsync;
}

bool
config_get_shuffle_uris(void)
{
	return config.shuffle_uris;
}

unsigned int
config_get_max_cert_depth(void)
{
	return config.maximum_certificate_depth;
}
