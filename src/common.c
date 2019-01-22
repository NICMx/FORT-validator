#include "common.h"

#include <errno.h>
#include <string.h>
#include "log.h"

char const *repository;
size_t repository_len;
int NID_rpkiManifest;
int NID_signedObject;
int NID_rpkiNotify;
