/*
 * Rule: MEM31-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM31-C violation
 */

/*
 * Rule: MEM31-C - Free dynamically allocated memory when no longer needed
 * Status: PASS
 * Reason: Storing a block through an out-parameter (`*out = p`) hands it to
 * the caller, exactly as returning it does. The same holds for a store into
 * a field or element, with or without a cast on the pointer. None of these
 * functions still owns the block at its return.
 */

#include <stdlib.h>

struct node { struct node *next; };
struct list { struct node *head; void *slots[4]; };

int out_param_plain(void **out)
{
	void *p = malloc(8);
	if (!p)
		return -1;
	*out = p;
	return 0;
}

int out_param_after_goto_guard(void **publ, void **priv)
{
	void *pubkey = NULL, *privkey = NULL;
	pubkey = malloc(8);
	if (!pubkey)
		goto err;
	privkey = malloc(8);
	if (!privkey)
		goto err;
	*publ = pubkey;
	*priv = privkey;
	return 0;
err:
	free(pubkey);
	free(privkey);
	return -1;
}

int out_param_cast(struct node **out)
{
	void *p = malloc(sizeof(struct node));
	if (!p)
		return -1;
	*out = (struct node *) p;
	return 0;
}

int field_store_cast(struct list *l)
{
	void *p = malloc(sizeof(struct node));
	if (!p)
		return -1;
	l->head = (struct node *) p;
	return 0;
}

int element_store(struct list *l, int i)
{
	void *p = malloc(8);
	if (!p)
		return -1;
	l->slots[i] = p;
	return 0;
}
