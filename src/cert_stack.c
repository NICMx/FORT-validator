#include "cert_stack.h"

#include <sys/queue.h>

#include "resource.h"
#include "str_token.h"
#include "thread_var.h"
#include "data_structure/array_list.h"
#include "object/name.h"

enum defer_node_type {
	DNT_SEPARATOR,
	DNT_CERT,
};

struct defer_node {
	enum defer_node_type type;

	/**
	 * This field is only relevant if @type == PCT_CERT.
	 * Do not dereference members otherwise.
	 */
	struct deferred_cert deferred;

	/** Used by certstack. Points to the next stacked certificate. */
	SLIST_ENTRY(defer_node) next;
};

SLIST_HEAD(defer_stack, defer_node);

struct serial_number {
	BIGNUM *number;
	char *file; /* File where this serial number was found. */
};

STATIC_ARRAY_LIST(serial_numbers, struct serial_number)

struct subject_name {
	struct rfc5280_name *name;
	char *file; /* File where this subject name was found. */
};

STATIC_ARRAY_LIST(subjects, struct subject_name)

/**
 * Cached certificate data.
 */
struct metadata_node {
	struct rpki_uri *uri;
	struct resources *resources;
	/*
	 * Serial numbers of the children.
	 * This is an unsorted array list for two reasons: Certificates usually
	 * don't have many children, and I'm running out of time.
	 */
	struct serial_numbers serials;
	struct subjects subjects;

	/** Used by certstack. Points to the next stacked certificate. */
	SLIST_ENTRY(metadata_node) next;
};

SLIST_HEAD(metadata_stack, metadata_node);

/**
 * Certificate repository "level". This aims to identify if the
 * certificate is located at a distinct server than its father (common
 * case when the RIRs delegate RPKI repositories).
 */
struct repo_level_node {
	unsigned int level;
	SLIST_ENTRY(repo_level_node) next;
};

SLIST_HEAD(repo_level_stack, repo_level_node);

/**
 * This is the foundation through which we pull off our iterative traversal,
 * as opposed to a stack-threatening recursive one.
 *
 * It is a bunch of data that replaces the one that would normally be allocated
 * in the function stack.
 */
struct cert_stack {
	/**
	 * Defer stack. Certificates we haven't iterated through yet.
	 *
	 * Every time a certificate validates successfully, its children are
	 * stored here so they can be traversed later.
	 */
	struct defer_stack defers;

	/**
	 * x509 stack. Parents of the certificate we're currently iterating
	 * through.
	 * Formatted for immediate libcrypto consumption.
	 */
	STACK_OF(X509) *x509s;

	/**
	 * Stacked additional data to each @x509 certificate.
	 *
	 * (These two stacks should always have the same size. The reason why I
	 * don't combine them is because libcrypto's validation function needs
	 * the X509 stack, and I'm not creating it over and over again.)
	 *
	 * (This is a SLIST and not a STACK_OF because the OpenSSL stack
	 * implementation is different than the LibreSSL one, and the latter is
	 * seemingly not intended to be used outside of its library.)
	 */
	struct metadata_stack metas;

	/**
	 * Stacked data to store the repository "levels" (each level is a
	 * delegation of an RPKI server).
	 */
	struct repo_level_stack levels;
};

int
certstack_create(struct cert_stack **result)
{
	struct cert_stack *stack;

	stack = malloc(sizeof(struct cert_stack));
	if (stack == NULL)
		return pr_enomem();

	stack->x509s = sk_X509_new_null();
	if (stack->x509s == NULL) {
		free(stack);
		return val_crypto_err("sk_X509_new_null() returned NULL");
	}

	SLIST_INIT(&stack->defers);
	SLIST_INIT(&stack->metas);
	SLIST_INIT(&stack->levels);

	*result = stack;
	return 0;
}

static void
defer_destroy(struct defer_node *defer)
{
	switch (defer->type) {
	case DNT_SEPARATOR:
		break;
	case DNT_CERT:
		uri_refput(defer->deferred.uri);
		rpp_refput(defer->deferred.pp);
		break;
	}

	free(defer);
}

static void
serial_cleanup(struct serial_number *serial)
{
	BN_free(serial->number);
	free(serial->file);
}

static void
subject_cleanup(struct subject_name *subject)
{
	x509_name_put(subject->name);
	free(subject->file);
}

static void
meta_destroy(struct metadata_node *meta)
{
	uri_refput(meta->uri);
	resources_destroy(meta->resources);
	serial_numbers_cleanup(&meta->serials, serial_cleanup);
	subjects_cleanup(&meta->subjects, subject_cleanup);
	free(meta);
}

void
certstack_destroy(struct cert_stack *stack)
{
	unsigned int stack_size;
	struct metadata_node *meta;
	struct defer_node *post;
	struct repo_level_node *level;

	stack_size = 0;
	while (!SLIST_EMPTY(&stack->defers)) {
		post = SLIST_FIRST(&stack->defers);
		SLIST_REMOVE_HEAD(&stack->defers, next);
		defer_destroy(post);
		stack_size++;
	}
	pr_val_debug("Deleted %u deferred certificates.", stack_size);

	pr_val_debug("Deleting %d stacked x509s.", sk_X509_num(stack->x509s));
	sk_X509_pop_free(stack->x509s, X509_free);

	stack_size = 0;
	while (!SLIST_EMPTY(&stack->metas)) {
		meta = SLIST_FIRST(&stack->metas);
		SLIST_REMOVE_HEAD(&stack->metas, next);
		meta_destroy(meta);
		stack_size++;
	}
	pr_val_debug("Deleted %u metadatas.", stack_size);

	stack_size = 0;
	while (!SLIST_EMPTY(&stack->levels)) {
		level = SLIST_FIRST(&stack->levels);
		SLIST_REMOVE_HEAD(&stack->levels, next);
		free(level);
		stack_size++;
	}
	pr_val_debug("Deleted %u stacked levels.", stack_size);

	free(stack);
}

int
deferstack_push(struct cert_stack *stack, struct deferred_cert *deferred)
{
	struct defer_node *node;

	node = malloc(sizeof(struct defer_node));
	if (node == NULL)
		return pr_enomem();

	node->type = DNT_CERT;
	node->deferred = *deferred;
	uri_refget(deferred->uri);
	rpp_refget(deferred->pp);
	SLIST_INSERT_HEAD(&stack->defers, node, next);
	return 0;
}

static void
x509stack_pop(struct cert_stack *stack)
{
	X509 *cert;
	struct metadata_node *meta;
	struct repo_level_node *repo;

	cert = sk_X509_pop(stack->x509s);
	if (cert == NULL)
		pr_crit("Attempted to pop empty X509 stack");
	X509_free(cert);

	meta = SLIST_FIRST(&stack->metas);
	if (meta == NULL)
		pr_crit("Attempted to pop empty metadata stack");
	SLIST_REMOVE_HEAD(&stack->metas, next);
	meta_destroy(meta);

	repo = SLIST_FIRST(&stack->levels);
	if (repo == NULL)
		pr_crit("Attempted to pop empty repo level stack");
	SLIST_REMOVE_HEAD(&stack->levels, next);
	free(repo);
}

/**
 * Contract: Returns either 0 or -ENOENT. No other outcomes.
 */
int
deferstack_pop(struct cert_stack *stack, struct deferred_cert *result)
{
	struct defer_node *node;

again:	node = SLIST_FIRST(&stack->defers);
	if (node == NULL)
		return -ENOENT;

	if (node->type == DNT_SEPARATOR) {
		x509stack_pop(stack);

		SLIST_REMOVE_HEAD(&stack->defers, next);
		defer_destroy(node);
		goto again;
	}

	*result = node->deferred;
	uri_refget(node->deferred.uri);
	rpp_refget(node->deferred.pp);

	SLIST_REMOVE_HEAD(&stack->defers, next);
	defer_destroy(node);
	return 0;
}

bool
deferstack_is_empty(struct cert_stack *stack)
{
	return SLIST_EMPTY(&stack->defers);
}

/** Steals ownership of @x509 on success. */
int
x509stack_push(struct cert_stack *stack, struct rpki_uri *uri, X509 *x509,
    enum rpki_policy policy, enum cert_type type)
{
	struct metadata_node *meta;
	struct repo_level_node *repo, *head_repo;
	struct defer_node *defer_separator;
	unsigned int work_repo_level;
	int ok;
	int error;

	repo = malloc(sizeof(struct repo_level_node));
	if (repo == NULL)
		return pr_enomem();

	repo->level = 0;
	work_repo_level = working_repo_peek_level();
	head_repo = SLIST_FIRST(&stack->levels);
	if (head_repo != NULL && work_repo_level > head_repo->level)
		repo->level = work_repo_level;

	SLIST_INSERT_HEAD(&stack->levels, repo, next);

	meta = malloc(sizeof(struct metadata_node));
	if (meta == NULL) {
		error = pr_enomem();
		goto end3;
	}

	meta->uri = uri;
	uri_refget(uri);
	serial_numbers_init(&meta->serials);
	subjects_init(&meta->subjects);

	meta->resources = resources_create(false);
	if (meta->resources == NULL) {
		error = pr_enomem();
		goto end4;
	}
	resources_set_policy(meta->resources, policy);
	error = certificate_get_resources(x509, meta->resources, type);
	if (error)
		goto end5;

	/*
	 * rfc8630#section-2.3
	 * "The INR extension(s) of this TA MUST contain a non-empty set of
	 * number resources."
	 * The "It MUST NOT use the "inherit" form of the INR extension(s)"
	 * part is already handled in certificate_get_resources().
	 */
	if (type == TA && resources_empty(meta->resources)) {
		error = pr_val_err("Trust Anchor certificate does not define any number resources.");
		goto end5;
	}

	defer_separator = malloc(sizeof(struct defer_node));
	if (defer_separator == NULL) {
		error = pr_enomem();
		goto end5;
	}
	defer_separator->type = DNT_SEPARATOR;

	ok = sk_X509_push(stack->x509s, x509);
	if (ok <= 0) {
		error = val_crypto_err(
		    "Could not add certificate to trusted stack: %d", ok);
		goto end5;
	}

	SLIST_INSERT_HEAD(&stack->defers, defer_separator, next);
	SLIST_INSERT_HEAD(&stack->metas, meta, next);

	return 0;

end5:	resources_destroy(meta->resources);
end4:	subjects_cleanup(&meta->subjects, subject_cleanup);
	serial_numbers_cleanup(&meta->serials, serial_cleanup);
	uri_refput(meta->uri);
	free(meta);
end3:	free(repo);
	return error;
}

/**
 * This one is intended to revert a recent x509 push.
 * Reverts that particular push.
 *
 * (x509 stack elements are otherwise indirectly popped through
 * deferstack_pop().)
 */
void
x509stack_cancel(struct cert_stack *stack)
{
	struct defer_node *defer_separator;

	x509stack_pop(stack);

	defer_separator = SLIST_FIRST(&stack->defers);
	if (defer_separator == NULL)
		pr_crit("Attempted to pop empty defer stack");
	SLIST_REMOVE_HEAD(&stack->defers, next);
	defer_destroy(defer_separator);
}

X509 *
x509stack_peek(struct cert_stack *stack)
{
	return sk_X509_value(stack->x509s, sk_X509_num(stack->x509s) - 1);
}

/** Does not grab reference. */
struct rpki_uri *
x509stack_peek_uri(struct cert_stack *stack)
{
	struct metadata_node *meta = SLIST_FIRST(&stack->metas);
	return (meta != NULL) ? meta->uri : NULL;
}

struct resources *
x509stack_peek_resources(struct cert_stack *stack)
{
	struct metadata_node *meta = SLIST_FIRST(&stack->metas);
	return (meta != NULL) ? meta->resources : NULL;
}

unsigned int
x509stack_peek_level(struct cert_stack *stack)
{
	struct repo_level_node *repo = SLIST_FIRST(&stack->levels);
	return (repo != NULL) ? repo->level : 0;
}

static int
get_current_file_name(char **_result)
{
	char const *tmp;
	char *result;

	tmp = fnstack_peek();
	if (tmp == NULL)
		pr_crit("The file name stack is empty.");

	result = strdup(tmp);
	if (result == NULL)
		return pr_enomem();

	*_result = result;
	return 0;
}

/**
 * Intended to validate serial number uniqueness.
 * "Stores" the serial number in the current relevant certificate metadata,
 * and complains if there's a collision. That's all.
 *
 * This function will steal ownership of @number on success.
 */
int
x509stack_store_serial(struct cert_stack *stack, BIGNUM *number)
{
	struct metadata_node *meta;
	struct serial_number *cursor;
	array_index i;
	struct serial_number duplicate;
	char *string;
	int error;

	/* Remember to free @number if you return 0 but don't store it. */

	meta = SLIST_FIRST(&stack->metas);
	if (meta == NULL) {
		BN_free(number);
		return 0; /* The TA lacks siblings, so serial is unique. */
	}

	/*
	 * Note: This is is reported as a warning, even though duplicate serial
	 * numbers are clearly a violation of the RFC and common sense.
	 *
	 * But it cannot be simply upgraded into an error because we are
	 * realizing the problem too late; our traversal is depth-first, so we
	 * already approved the other bogus certificate and its children.
	 * (I don't think changing to a breath-first traversal would be a good
	 * idea; the RAM usage would skyrocket because, since we need the entire
	 * certificate path to the root to validate any certificate, we would
	 * end up having the entire tree loaded in memory by the time we're done
	 * traversing.)
	 *
	 * So instead of arbitrarily approving one certificate but not the
	 * other, we will accept both but report a warning.
	 *
	 * Also: It's pretty odd; a significant amount of certificates seem to
	 * be breaking this rule. Maybe we're the only ones catching it?
	 *
	 * TODO I haven't seen this warning in a while. Review.
	 */
	ARRAYLIST_FOREACH(&meta->serials, cursor, i) {
		if (BN_cmp(cursor->number, number) == 0) {
			BN2string(number, &string);
			pr_val_warn("Serial number '%s' is not unique. (Also found in '%s'.)",
			    string, cursor->file);
			BN_free(number);
			free(string);
			return 0;
		}
	}

	duplicate.number = number;
	error = get_current_file_name(&duplicate.file);
	if (error)
		return error;

	error = serial_numbers_add(&meta->serials, &duplicate);
	if (error)
		free(duplicate.file);

	return error;
}

/**
 * Intended to validate subject uniqueness.
 * "Stores" the subject in the current relevant certificate metadata, and
 * complains if there's a collision. The @cb should check the primary key of
 * the subject, it will be called when a subject isn't unique (certificate
 * shares the subject but not the public key). That's all.
 */
int
x509stack_store_subject(struct cert_stack *stack, struct rfc5280_name *subject,
    subject_pk_check_cb cb, void *arg)
{
	struct metadata_node *meta;
	struct subject_name *cursor;
	array_index i;
	struct subject_name duplicate;
	bool duplicated;
	int error;

	/*
	 * There's something that's not clicking with me:
	 *
	 * "Each distinct subordinate CA and
	 * EE certified by the issuer MUST be identified using a subject name
	 * that is unique per issuer.  In this context, 'distinct' is defined as
	 * an entity and a given public key."
	 *
	 * Does the last sentence have any significance to us? I don't even
	 * understand why the requirement exists. 5280 and 6487 don't even
	 * define "entity." We'll take the closest definition from the context,
	 * specifically from RFC 6484 or RFC 6481 (both RFCs don't define
	 * "entity" explicitly, but use the word in a way that it can be
	 * inferred what it means).
	 *
	 * "An issuer SHOULD use a different
	 * subject name if the subject's key pair has changed (i.e., when the CA
	 * issues a certificate as part of re-keying the subject.)"
	 *
	 * It's really weird that it seems to be rewording the same requirement
	 * except the first version is defined as MUST and the second one is
	 * defined as SHOULD.
	 *
	 * Ugh. Okay. Let's use some common sense. There are four possible
	 * situations:
	 *
	 * - Certificates do not share name nor public key. We should accept
	 *   this.
	 * - Certificates share name, but not public key. We should reject this.
	 * - Certificates share public key, but not name. This is basically
	 *   impossible, but fine nonetheless. Accept.
	 *   (But maybe issue a warning. It sounds like the two children can
	 *   impersonate each other.)
	 * - Certificates share name and public key. This likely means that we
	 *   are looking at two different versions of the same certificate.
	 *   Accept. (see rfc6484#section-4.7.1 for an example)
	 *
	 */

	meta = SLIST_FIRST(&stack->metas);
	if (meta == NULL)
		return 0; /* The TA lacks siblings, so subject is unique. */

	/* See the large comment in certstack_x509_store_serial(). */
	duplicated = false;
	ARRAYLIST_FOREACH(&meta->subjects, cursor, i) {
		if (x509_name_equals(cursor->name, subject)) {
			error = cb(&duplicated, cursor->file, arg);
			if (error)
				return error;

			if (!duplicated)
				continue;

			char const *serial = x509_name_serialNumber(subject);
			pr_val_warn("Subject name '%s%s%s' is not unique. (Also found in '%s'.)",
			    x509_name_commonName(subject),
			    (serial != NULL) ? "/" : "",
			    (serial != NULL) ? serial : "",
			    cursor->file);
			return 0;
		}
	}

	duplicate.name = subject;
	x509_name_get(subject);

	error = get_current_file_name(&duplicate.file);
	if (error)
		goto revert_name;

	error = subjects_add(&meta->subjects, &duplicate);
	if (error)
		goto revert_file;

	return 0;

revert_file:
	free(duplicate.file);
revert_name:
	x509_name_put(subject);
	return error;
}

STACK_OF(X509) *
certstack_get_x509s(struct cert_stack *stack)
{
	return stack->x509s;
}

int
certstack_get_x509_num(struct cert_stack *stack)
{
	return sk_X509_num(stack->x509s);
}
