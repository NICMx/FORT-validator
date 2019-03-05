#include "object/name.h"

#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include "log.h"
#include "thread_var.h"

static int
name2string(X509_NAME_ENTRY *name, char **_result)
{
	const ASN1_STRING *data;
	char *result;

	data = X509_NAME_ENTRY_get_data(name);
	if (data == NULL)
		return crypto_err("X509_NAME_ENTRY_get_data() returned NULL");

	result = malloc(data->length + 1);
	if (result == NULL)
		return pr_enomem();

	memcpy(result, data->data, data->length);
	result[data->length] = '\0';

	*_result = result;
	return 0;
}

int
x509_name_decode(X509_NAME *name, char const *what,
    struct rfc5280_name *result)
{
	int i;
	X509_NAME_ENTRY *entry;
	int nid;
	int error;

	result->commonName = NULL;
	result->serialNumber = NULL;

	for (i = 0; i < X509_NAME_entry_count(name); i++) {
		entry = X509_NAME_get_entry(name, i);
		nid = OBJ_obj2nid(X509_NAME_ENTRY_get_object(entry));
		switch (nid) {
		case NID_commonName:
			error = name2string(entry, &result->commonName);
			break;
		case NID_serialNumber:
			error = name2string(entry, &result->serialNumber);
			break;
		default:
			error = pr_err("The '%s' name has an unknown attribute. (NID: %d)",
			    what, nid);
			break;
		}

		if (error)
			goto fail;
	}

	if (result->commonName == NULL) {
		error = pr_err("The '%s' name lacks a commonName attribute.",
		    what);
		goto fail;
	}

	return 0;

fail:
	x509_name_cleanup(result);
	return error;
}

void
x509_name_cleanup(struct rfc5280_name *name)
{
	free(name->commonName);
	free(name->serialNumber);
}

/**
 * Also checks NULL.
 *
 * Does assume that @str1 and @str2 are NULL-terminated.
 */
static bool str_equals(char const *str1, char const *str2)
{
	if (str1 == str2)
		return true;
	if (str1 == NULL || str2 == NULL)
		return false;
	return strcmp(str1, str2) == 0;
}

bool
x509_name_equals(struct rfc5280_name *a, struct rfc5280_name *b)
{
	return (strcmp(a->commonName, b->commonName) == 0)
	    && str_equals(a->serialNumber, b->serialNumber);
}

int
validate_issuer_name(char const *container, X509_NAME *issuer)
{
	struct validation *state;
	X509 *parent;
	struct rfc5280_name parent_subject;
	struct rfc5280_name child_issuer;
	int error;

	/*
	 * Not sure whether "the CRL issuer is the CA" means that the issuer
	 * name should equal the parent's subject name or not, because that's
	 * very much not what rfc6487#section-4.4 is asking us to check.
	 * But let's check it anyway.
	 */

	state = state_retrieve();
	if (state == NULL)
		return -EINVAL;
	parent = validation_peek_cert(state);
	if (parent == NULL) {
		return pr_err("%s appears to have no parent certificate.",
		    container);
	}

	error = x509_name_decode(X509_get_subject_name(parent), "subject",
	    &parent_subject);
	if (error)
		return error;
	error = x509_name_decode(issuer, "issuer", &child_issuer);
	if (error)
		goto end;

	if (!x509_name_equals(&parent_subject, &child_issuer)) {
		error = pr_err("%s's issuer name ('%s%s%s') does not equal issuer certificate's name ('%s%s%s').",
		    container,
		    parent_subject.commonName,
		    (parent_subject.serialNumber != NULL) ? "/" : "",
		    (parent_subject.serialNumber != NULL)
		        ? parent_subject.serialNumber
		        : "",
		    child_issuer.commonName,
		    (child_issuer.serialNumber != NULL) ? "/" : "",
		    (child_issuer.serialNumber != NULL)
		        ? child_issuer.serialNumber
		        : "");
	}

	x509_name_cleanup(&child_issuer);
end:	x509_name_cleanup(&parent_subject);
	return error;
}
