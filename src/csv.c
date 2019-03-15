#include "csv.h"

#include <err.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#include "configuration.h"
#include "address.h"
#include "line_file.h"
#include "vrps.h"

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
parse_asn(char *text, unsigned int *value)
{
	unsigned long asn;
	char *start;

	if (text == NULL) {
		err(-EINVAL, "Null string received, can't decode ASN");
		return -EINVAL;
	}

	/* The text 'AS' may precede the number */
	start = strchr(text, 'S');
	start = start != NULL ? start + 1 : text;

	errno = 0;
	asn = strtoul(start, NULL, 10);
	if (errno) {
		err(errno, "Invalid ASN '%s': %s", text, strerror(errno));
		return -EINVAL;
	}
	/* An underflow or overflow will be considered here */
	if (asn < 0 || UINT32_MAX < asn) {
		err(-EINVAL, "Prefix length (%lu) is out of bounds (0-%u).",
			asn, UINT32_MAX);
		return -EINVAL;
	}
	*value = (unsigned int) asn;

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
add_vrp(char *line, struct delta *delta)
{
	struct ipv4_prefix prefixv4;
	struct ipv6_prefix prefixv6;
	struct vrp *vrp;
	unsigned int asn, prefix_length, max_prefix_length;
	int error;
	bool isv4;
	char *token, *line_copy;

	line_copy = malloc(strlen(line) + 1);
	if (line_copy == NULL) {
		error = -ENOMEM;
		err(error, "Out of memory allocating CSV line copy");
		goto error;
	}
	strcpy(line_copy, line);

	error = 0;

	/* First column: ASN in format "AS###" */
	token = strtok(line_copy, ",");
	error = parse_asn(token, &asn);
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
	error = parse_prefix_length(token, isv4 ? &prefixv4.len : &prefixv6.len,
	    isv4 ? 32 : 128);
	if (error)
		goto error;

	/* Third column: Prefix max length in numeric format */
	token = strtok(NULL, ",");
	error = parse_prefix_length(token, &max_prefix_length, isv4 ? 32 : 128);
	if (error)
		goto error;

	/* Now validate the prefix */
	if (isv4) {
		prefix_length = prefixv4.len;
		error = prefix4_validate(&prefixv4);
	} else {
		prefix_length = prefixv6.len;
		error = prefix6_validate(&prefixv6);
	}
	if (error)
		goto error;

	if (prefix_length > max_prefix_length) {
		error = -EINVAL;
		err(error, "Prefix length is greater than max prefix length at line '%s'",
		    line);
		goto error;
	}

	if (isv4)
		vrp = create_vrp4(asn, prefixv4.addr, prefixv4.len, max_prefix_length);
	else
		vrp = create_vrp6(asn, prefixv6.addr, prefixv6.len, max_prefix_length);

	if (vrp == NULL) {
		error = -ENOMEM;
		err(error, "Couldn't allocate VRP of line '%s'", line);
		goto error;
	}

	error = delta_add_vrp(delta, vrp);
	if (error) {
		vrp_destroy(vrp);
		goto error;
	}

	return 0;

error:
	free(line_copy);
	return error;
}

static int
load_vrps(struct line_file *lfile, bool is_update)
{
	struct delta *delta;
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
		err(error, "Empty CSV file, stop processing.");
		return error;
	}
	/* Start the initial delta */
	delta = create_delta();
	do {
		++current_line;
		error = lfile_read(lfile, &line);
		if (error) {
			err(error, "Error reading line %d, stop processing file.", current_line);
			delta_destroy(&delta);
			goto end;
		}
		if (line == NULL) {
			error = 0;
			goto persist;
		}
		if (strcmp(line, "") == 0) {
			warn("There's nothing at line %d, ignoring.", current_line);
			continue;
		}

		error = add_vrp(line, delta);
		if (error) {
			delta_destroy(&delta);
			goto end;
		}
	} while (true);
persist:
	error = deltas_db_add_delta(delta);
	if (error)
		err(error, "VRPs Delta couldn't be persisted");
end:
	if (line != NULL)
		free(line);
	return error;
}

static int
load_vrps_file(bool check_update, bool *updated)
{

	struct line_file *lfile;
	struct stat attr;
	time_t last_update;
	char const *location;
	int error;

	location = config_get_vrps_location();
	if (!location_has_extension(location, ".csv")) {
		warn("%s isn't a CSV file", location);
		error = -EINVAL;
		goto end1;
	}

	error = lfile_open(location, &lfile);
	if (error)
		goto end1; /* Error msg already printed. */

	// Look for the last update date
	error = stat(location, &attr);
	if (error) {
		warn("Couldn't get last modified date of %s, skip update",
			location);
		goto end2;
	}

	last_update = attr.st_mtim.tv_sec;
	if (check_update && last_update <= get_vrps_last_modified_date())
		goto end2;

	error = load_vrps(lfile, check_update);
	if (error)
		goto end2;

	if (updated != NULL)
		*updated = check_update && last_update > get_vrps_last_modified_date();

	set_vrps_last_modified_date(last_update);
	// TODO Double check of date

end2:
	lfile_close(lfile);
end1:
	return error;
}

int
csv_parse_vrps_file()
{
	return load_vrps_file(false, NULL);
}

int
csv_check_vrps_file(bool *updated)
{
	return load_vrps_file(true, updated);
}
