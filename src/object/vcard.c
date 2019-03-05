#include "vcard.h"

#include <errno.h>
#include <stdbool.h>

#include "log.h"

/*
 * TODO (next iteration) Implement RFC 6350.
 * (The current code implements RFC 6493 *only*.)
 */

/**
 * Reminder: UTF-8 strings are **not** C strings.
 * They can contain null characters, which do not terminate them.
 * DO NOT use standard string operations on them. (Unless you know what you're
 * doing).
 */
struct utf8_string {
	uint8_t *val;
	/** Number of bytes in @val. */
	size_t len;
	/** Actual allocated size of @val. */
	size_t size;
};

struct vcard_line {
	/**
	 * This is a copy of the actual vCard value.
	 * It does not include the newline and has folding characters removed.
	 */
	struct utf8_string str;
	size_t octet_string_offset;
};

enum string_analysis {
	SA_COPY_CHARA,
	SA_LINE_ENDED,
	SA_SKIP_THREE_CHARAS,
	SA_ERROR,
};

/**
 * Returns a pointer to the character at the right of string[pos], if it exists.
 *
 * Assumes that string->len > 0.
 */
static uint8_t *
next_chara(struct utf8_string *string, size_t pos)
{
	return (pos < string->len - 1) ? (string->val + pos + 1) : NULL;
}

/**
 * Assumes that pos < string_len and that string_len > 0.
 */
static enum string_analysis
analyze_pos(struct utf8_string *string, size_t pos)
{
	/*
	 * Special cases:
	 *
	 * 1. \r\n: Normal line/property end
	 * 2. \r\n\w (where '\w' is space or tab): Folded line
	 *
	 * Each vCard line must end with \r\n.
	 */

	uint8_t *next1;
	uint8_t *next2;

	if (string->val[pos] != '\r')
		return SA_COPY_CHARA; /* Typical path */

	/* At this point, we have a \r. */

	next1 = next_chara(string, pos);
	if (next1 == NULL) {
		pr_err("vCard's final newline is incomplete ('\\r').");
		return SA_ERROR;
	}
	if (*next1 != '\n')
		return SA_COPY_CHARA; /* Random stray \r; no problem for now. */

	/* At this point, we have a \r\n. */

	next2 = next_chara(string, pos + 1);
	if (next2 == NULL)
		return SA_LINE_ENDED; /* \r\n<eof> */
	if (*next2 == ' ' || *next2 == '\t')
		return SA_SKIP_THREE_CHARAS; /* Folded line */

	return SA_LINE_ENDED; /* \r\n<more lines> */
}

static int
double_line_size(struct vcard_line *line)
{
	uint8_t *tmp;

	line->str.size *= 2;
	tmp = realloc(line->str.val, line->str.size);
	if (tmp == NULL)
		return pr_enomem();
	line->str.val = tmp;

	return 0;
}

static int
add_chara(struct vcard_line *line, uint8_t chara, bool inc_str_len)
{
	int error;

	if (line->str.len + 1 == line->str.size) {
		error = double_line_size(line);
		if (error)
			return error;
	}

	line->str.val[line->str.len] = chara;
	if (inc_str_len)
		line->str.len++;

	return 0;
}

/**
 * Will remove the newline (\r\n). Just assume that there is a valid newline at
 * the end.
 * The result will not be a C string, but will still have a null character at
 * the end (not accounted by line->str.len), in case you want to print it.
 */
static int
line_next(struct vcard_line *line, OCTET_STRING_t *string8)
{
	struct utf8_string string;
	size_t string_pos;
	int error;

	if (string8->size == line->octet_string_offset)
		return pr_err("vCard ends prematurely. (Expected an END line)");

	string.val = string8->buf + line->octet_string_offset;
	string.len = string8->size - line->octet_string_offset;
	string.size = 0;
	line->str.len = 0;

	for (string_pos = 0; string_pos < string.len; string_pos++) {
		switch (analyze_pos(&string, string_pos)) {
		case SA_COPY_CHARA:
			error = add_chara(line, string.val[string_pos], true);
			if (error)
				return error;
			break;

		case SA_LINE_ENDED:
			line->octet_string_offset += string_pos + 2;
			return add_chara(line, 0, false);

		case SA_SKIP_THREE_CHARAS:
			string_pos += 2;
			break;

		case SA_ERROR:
			return -EINVAL;
		}
	}

	return pr_err("vCard line does not end with a \\r\\n-style newline.");
}

static int
line_validate(struct vcard_line *line, char const *expected)
{
	size_t expected_len = strlen(expected);

	if (line->str.len != expected_len)
		goto fail;

	/*
	 * RFC 6350:
	 * "Property names and parameter names are case-insensitive"
	 * "Parameter values that are not explicitly defined as being
	 * case-sensitive are case-insensitive."
	 */
	if (strncasecmp((char *) line->str.val, expected, expected_len) != 0)
		goto fail;

	return 0;

fail:
	return pr_err("Expected vCard property '%s', got '%s'.",
	    expected, line->str.val);
}

/**
 * @tag must contain the colon. This simplifies the code.
 */
static int
line_starts_with(struct vcard_line *line, char const *tag)
{
	/* RFC6350: "Property names and parameter names are case-insensitive" */
	return strncasecmp((char *) line->str.val, tag, strlen(tag)) == 0;
}

static int
__handle_ghostbusters_vcard(OCTET_STRING_t *vcard, struct vcard_line *line)
{
	bool fn_found = false;
	bool useful_found = false;
	int error;

	error = line_next(line, vcard);
	if (error)
		return error;
	error = line_validate(line, "BEGIN:VCARD");
	if (error)
		return error;

	error = line_next(line, vcard);
	if (error)
		return error;
	error = line_validate(line, "VERSION:4.0");
	if (error)
		return error;

	do {
		error = line_next(line, vcard);
		if (error)
			return error;

		if (line_starts_with(line, "FN:")) {
			fn_found = true;

		} else if (line_starts_with(line, "ORG:")
		    || line_starts_with(line, "ADR:")
		    || line_starts_with(line, "TEL:")
		    || line_starts_with(line, "EMAIL:")) {
			useful_found = true;

		} else if (line_starts_with(line, "END:")) {
			break;

		} else {
			return pr_err("Unexpected vCard line: '%s'",
			    line->str.val);
		}

	} while (true);

	error = line_validate(line, "END:VCARD");
	if (error)
		return error;
	if (vcard->size != line->octet_string_offset)
		return pr_err("vCard has content after the END tag.");

	if (!fn_found)
		return pr_err("vCard lacks the 'FN' property.");
	if (!useful_found)
		return pr_err("vCard lacks the 'ORG', 'ADR', 'TEL' and/or 'EMAIL' properties.");

	return 0;
}

int
handle_ghostbusters_vcard(OCTET_STRING_t *vcard)
{
	struct vcard_line line;
	int error;

	line.str.size = 81; /* Okay default, assuming there is no folding. */
	line.str.len = 0;
	line.str.val = malloc(line.str.size);
	if (line.str.val == NULL)
		return pr_enomem();
	line.octet_string_offset = 0;

	error = __handle_ghostbusters_vcard(vcard, &line);

	free(line.str.val);
	return error;
}
