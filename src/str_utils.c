#include "str_utils.h"

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <regex.h>
#include "types.h"


#define MAX_PORT 0xFFFF

int
validate_int(const char *str)
{
	regex_t integer_regex;
	int error;

	if (!str) {
		log_err0("Programming error: 'str' is NULL.");
		return -EINVAL;
	}

	/* It seems this RE implementation doesn't understand '+'. */
	if (regcomp(&integer_regex, "^[0-9][0-9]*", 0)) {
		log_err0("Warning: Integer regex didn't compile.");
		log_err0("(I will be unable to validate integer inputs.)");
		regfree(&integer_regex);
		/*
		 * Don't punish the user over our incompetence.
		 * If the number is valid, this will not bother the user.
		 * Otherwise strtoull() will just read a random value, but then
		 * the user is at fault.
		 */
		return 0;
	}

	error = regexec(&integer_regex, str, 0, NULL, 0);
	if (error) {
		log_err("'%s' is not a number. (error code %d)", str, error);
		regfree(&integer_regex);
		return error;
	}

	regfree(&integer_regex);
	return 0;
}

static int
str_to_ull(const char *str, char **endptr,
		const unsigned long long int min,
		const unsigned long long int max,
		unsigned long long int *result)
{
	unsigned long long int parsed;
	int error;

	error = validate_int(str);
	if (error)
		return error;

	errno = 0;
	parsed = strtoull(str, endptr, 10);
	if (errno) {
		log_err("Parsing of '%s' threw error code %d.", str, errno);
		return errno;
	}

	if (parsed < min || max < parsed) {
		log_err("'%s' is out of bounds (%llu-%llu).", str, min, max);
		return -EINVAL;
	}

	*result = parsed;
	return 0;
}

int
str_to_bool(const char *str, __u8 *bool_out)
{
	if (strcasecmp(str, "true") == 0
			|| strcasecmp(str, "1") == 0
			|| strcasecmp(str, "yes") == 0
			|| strcasecmp(str, "on") == 0) {
		*bool_out = true;
		return 0;
	}

	if (strcasecmp(str, "false") == 0
			|| strcasecmp(str, "0") == 0
			|| strcasecmp(str, "no") == 0
			|| strcasecmp(str, "off") == 0) {
		*bool_out = false;
		return 0;
	}

	log_err("Cannot parse '%s' as a bool (true|false|1|0|yes|no|on|off).",
			str);
	return -EINVAL;
}

int
str_to_u8(const char *str, __u8 *u8_out, __u8 min, __u8 max)
{
	unsigned long long int result;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);
	
	*u8_out = result;
	return error;
}

int
str_to_u16(const char *str, __u16 *u16_out, __u16 min, __u16 max)
{
	unsigned long long int result;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);

	*u16_out = result;
	return error;
}

int
str_to_u32(const char *str, __u32 *u32_out, __u32 min, __u32 max)
{
	unsigned long long int result;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);

	*u32_out = result;
	return error;
}

int
str_to_u64(const char *str, __u64 *u64_out, __u64 min, __u64 max)
{
	unsigned long long int result;
	int error;

	error = str_to_ull(str, NULL, min, max, &result);

	*u64_out = result;
	return error;
}

#define STR_MAX_LEN 2048
int
str_to_u16_array(const char *str, __u16 **array_out, size_t *array_len_out)
{
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	__u16 *array;
	size_t array_len;

	/* Validate str and copy it to the temp buffer. */
	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	/* Count the number of ints in the string. */
	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		array_len++;
		token = strtok(NULL, ",");
	}

	if (array_len == 0) {
		log_err("'%s' seems to be an empty list, which is not supported.", str);
		return -EINVAL;
	}

	/* Build the result. */
	array = malloc(array_len * sizeof(*array));
	if (!array) {
		log_err0("Memory allocation failed. Cannot parse the input...");
		return -ENOMEM;
	}

	strcpy(str_copy, str);

	array_len = 0;
	token = strtok(str_copy, ",");
	while (token) {
		int error;

		error = str_to_u16(token, &array[array_len], 0, 0xFFFF);
		if (error) {
			free(array);
			return error; /* Error msg already printed. */
		}

		array_len++;
		token = strtok(NULL, ",");
	}

	/* Finish. */
	*array_out = array;
	*array_len_out = array_len;
	return 0;
}

int
str_to_addr4(const char *str, struct in_addr *result)
{
	if (!inet_pton(AF_INET, str, result)) {
		log_err("Cannot parse '%s' as an IPv4 address.", str);
		return -EINVAL;
	}
	return 0;
}

int
str_to_addr6(const char *str, struct in6_addr *result)
{
	if (!inet_pton(AF_INET6, str, result)) {
		log_err("Cannot parse '%s' as an IPv6 address.", str);
		return -EINVAL;
	}
	return 0;
}

#undef STR_MAX_LEN
#define STR_MAX_LEN (INET_ADDRSTRLEN + 1 + 5) /* [addr + null chara] + # + port */
int
str_to_addr4_port(const char *str, struct ipv4_transport_addr *addr)
{
	const char *FORMAT = "<IPv4 address>#<port> (eg. 203.0.113.8#80)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token) {
		log_err("Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr4(token, &addr->l3);
	if (error)
		return error;

	token = strtok(NULL, "#");
	if (!token) {
		log_err("'%s' does not seem to contain a port (format: %s).", str, FORMAT);
		return -EINVAL;
	}
	return str_to_u16(token, &addr->l4, 0, MAX_PORT); /* Error msg already printed. */
}

#undef STR_MAX_LEN
#define STR_MAX_LEN (INET6_ADDRSTRLEN + 1 + 5) /* [addr + null chara] + # + port */
int
str_to_addr6_port(const char *str, struct ipv6_transport_addr *addr)
{
	const char *FORMAT = "<IPv6 address>#<port> (eg. 2001:db8::1#96)";
	/* strtok corrupts the string, so we'll be using this copy instead. */
	char str_copy[STR_MAX_LEN];
	char *token;
	int error;

	if (strlen(str) + 1 > STR_MAX_LEN) {
		log_err("'%s' is too long for this poor, limited parser...", str);
		return -EINVAL;
	}
	strcpy(str_copy, str);

	token = strtok(str_copy, "#");
	if (!token) {
		log_err("Cannot parse '%s' as a %s.", str, FORMAT);
		return -EINVAL;
	}

	error = str_to_addr6(token, &addr->l3);
	if (error)
		return error;

	token = strtok(NULL, "#");
	if (!token) {
		log_err("'%s' does not seem to contain a port (format: %s).", str, FORMAT);
		return -EINVAL;
	}
	return str_to_u16(token, &addr->l4, 0, MAX_PORT); /* Error msg already printed. */
}

bool
endsWith(char *string, char *suffix)
{
	size_t strilen;
	size_t suflen;
	if (!string || !suffix)
		return false;

	strilen = strlen(string);
	suflen = strlen(suffix);

	return ((strilen >= suflen) && (0 == strcmp(string + strilen - suflen, suffix)));
}
