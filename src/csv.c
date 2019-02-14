#include "csv.h"

#include <err.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "address.h"
#include "line_file.h"

struct csv_data {
	char *asn;
	char *prefix;
	int max_length;
	char *trust_anchor;
};

/* @ext must include the period. */
static bool
location_has_extension(char const *location, char const *ext)
{
	size_t ext_len, loc_len;
	int cmp;

	ext_len = strlen(ext);
	loc_len = strlen(location);
	if (loc_len < ext_len)
		return false;

	cmp = strncmp(location + loc_len - ext_len, ext, ext_len);
	return cmp == 0;
}

static int
parse_asn(char *text)
{
	if (text == NULL)
		return -EINVAL;
	return 0;
}

static int
parse_prefix4(char *text, struct ipv4_prefix *prefixv4)
{
	if (text == NULL)
		return -EINVAL;
	return prefix4_decode(text, prefixv4);
}

static int
parse_prefix6(char *text, struct ipv6_prefix *prefixv6)
{
	if (text == NULL)
		return -EINVAL;
	return prefix6_decode(text, prefixv6);
}

static int
parse_prefix_length(char *text, unsigned int *value, int max_value)
{
	if (text == NULL)
		return -EINVAL;
	return prefix_length_decode(text, value, max_value);
}

static int
add_vrp(char *line)
{
	struct ipv4_prefix prefixv4;
	struct ipv6_prefix prefixv6;
	unsigned int prefix_length, max_prefix_length;
	int error;
	bool isv4;
	char *token, *line_copy;

	line_copy = malloc(strlen(line) + 1);
	if (line_copy == NULL) {
		error = -ENOMEM;
		err(error, "Out of memory allocating CSV line copy");
	}
	strcpy(line_copy, line);

	error = 0;

	/* First column: ASN in format "AS###" */
	token = strtok(line_copy, ",");
	error = parse_asn(token);
	if (error)
		goto error;

	/* Second column (first part): Prefix in string format */
	token = strtok(NULL, "/");
	isv4 = strchr(token, ':') == NULL;
	if (isv4)
		error = parse_prefix4(token, &prefixv4);
	else
		error = parse_prefix6(token, &prefixv6);

	if (error)
		goto error;

	/* Second column (second part): Prefix length in numeric format */
	token = strtok(NULL, ",");
	error = parse_prefix_length(token, &prefix_length, isv4 ? 32 : 128);
	if (error)
		goto error;

	/* Third column: Prefix max length in numeric format */
	token = strtok(NULL, ",");
	error = parse_prefix_length(token, &max_prefix_length, isv4 ? 32 : 128);
	if (error)
		goto error;

	/* Now validate the prefix */
	if (isv4) {
		prefixv4.len = prefix_length;
		error = prefix4_validate(&prefixv4);
	} else {
		prefixv6.len = prefix_length;
		error = prefix6_validate(&prefixv6);
	}
	if (error)
		goto error;

	if (prefix_length > max_prefix_length) {
		error = -EINVAL;
		err(error, "Prefix length is greater than max prefix length [%u > %u]",
		    prefix_length, max_prefix_length);
	}

	/* TODO Now store the values in memory */
error:
	return error;
}

static int
read_vrps(struct line_file *lfile)
{
	char *line;
	int current_line;
	int error;

	/* First line is expected to be the header, ignore it */
	current_line = 1;
	error = lfile_read(lfile, &line);
	if (error) {
		err(error, "Error at first line, stop processing CSV file.");
		return error;
	}
	if (line == NULL) {
		error = -EINVAL;
		err(error, "Empty file, stop processing.");
		return error;
	}
	do {
		++current_line;
		error = lfile_read(lfile, &line);
		if (error) {
			err(error, "Error at line %d, stop processing file.", current_line);
			if (line != NULL)
				free(line);
			return error;
		}
		if (line == NULL) {
			free(line);
			return 0;
		}
		if (strcmp(line, "") == 0) {
			warn("There's nothing at line %d, ignoring.", current_line);
			continue;
		}

		error = add_vrp(line);
		if (error) {
			free(line);
			return error;
		}
	} while (true);
}

int
parse_file(char const *location)
{
	struct line_file *lfile;
	int error;

	if (!location_has_extension(location, ".csv")) {
		warn("%s isn't a CSV file", location);
		error = -EINVAL;
		goto end1;
	}

	error = lfile_open(location, &lfile);
	if (error)
		goto end1; /* Error msg already printed. */

	error = read_vrps(lfile);
	if (error)
		goto end2;

end2:
	lfile_close(lfile);
end1:
	return error;
}
