#include "common.h"

#include <errno.h>
#include <string.h>
#include "log.h"
#include "thread_var.h"

int NID_rpkiManifest;
int NID_signedObject;
int NID_rpkiNotify;
int NID_certPolicyRpki;
int NID_certPolicyRpkiV2;

/**
 * Does not assume that @string is NULL-terminated.
 */
int
string_clone(void const *string, size_t size, char **clone)
{
	char *result;

	result = malloc(size + 1);
	if (result == NULL)
		return pr_enomem();

	memcpy(result, string, size);
	result[size] = '\0';

	*clone = result;
	return 0;
}

int
ia5s2string(ASN1_IA5STRING *ia5, char **result)
{
	return (ia5->flags & ASN1_STRING_FLAG_BITS_LEFT)
	    ? pr_err("CRL URI IA5String has unused bits.")
	    : string_clone(ia5->data, ia5->length, result);
}

/**
 * Only prints error message if the result is not 0 nor -ESRCH.
 */
int
x509_name_decode(X509_NAME *name, int nid, char **_result)
{
	char *result;
	int len1, len2;

	len1 = X509_NAME_get_text_by_NID(name, nid, NULL, 0);
	if (len1 < 0)
		return -ESRCH;

	if (_result == NULL)
		return 0;

	result = calloc(len1 + 1, sizeof(char));
	if (result == NULL)
		return pr_enomem();

	len2 = X509_NAME_get_text_by_NID(name, nid, result, len1 + 1);
	if (len1 != len2) {
		free(result);
		return pr_err("Likely programming error: X509_NAME_get_text_by_NID() returned inconsistent lengths: %d,%d",
		    len1, len2);
	}

	*_result = result;
	return 0;
}

struct rfc5280_names {
	char *commonName;
	char *serialNumber;
};

static int
get_names(X509_NAME *name, char *what, struct rfc5280_names *result)
{
	int error;

	error = x509_name_decode(name, NID_commonName, &result->commonName);
	if (error == -ESRCH)
		return pr_err("The '%s' name lacks a commonName attribute.");
	if (error)
		return error;

	error = x509_name_decode(name, NID_serialNumber, &result->serialNumber);
	if (error == -ESRCH) {
		result->serialNumber = NULL;
		return 0;
	}
	if (error) {
		free(result->commonName);
		return error;
	}

	return 0;
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

int
validate_issuer_name(char const *container, X509_NAME *issuer)
{
	struct validation *state;
	X509 *parent;
	struct rfc5280_names parent_subject = { 0 };
	struct rfc5280_names child_issuer = { 0 };
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

	error = get_names(X509_get_subject_name(parent), "subject",
	    &parent_subject);
	if (error)
		return error;
	error = get_names(issuer, "issuer", &child_issuer);
	if (error)
		goto end2;

	if (strcmp(parent_subject.commonName, child_issuer.commonName) != 0) {
		error = pr_err("%s's issuer commonName ('%s') does not equal issuer certificate's commonName ('%s').",
		    container, parent_subject.commonName,
		    child_issuer.commonName);
		goto end1;
	}

	if (!str_equals(parent_subject.serialNumber,
	    child_issuer.serialNumber)) {
		error = pr_err("%s's issuer serialNumber ('%s') does not equal issuer certificate's serialNumber ('%s').",
		    container, parent_subject.serialNumber,
		    child_issuer.serialNumber);
		goto end1;
	}

end1:
	free(child_issuer.commonName);
	free(child_issuer.serialNumber);
end2:
	free(parent_subject.commonName);
	free(parent_subject.serialNumber);
	return error;
}
