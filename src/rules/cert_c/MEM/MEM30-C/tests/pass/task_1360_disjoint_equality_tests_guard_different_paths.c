/*
 * Rule: MEM30-C
 * Source: valkey src/call_reply.c freeCallReplyInternal(), sqlite
 *         src/update.c updateVirtualTable() (task 1360)
 * Status: PASS - Should NOT trigger MEM30-C violation
 *
 * Two `if`s in a row on the same value, each against constants: a reply
 * has one type, so the arm for MAP never runs on a reply whose ARRAY arm
 * freed the array; the else of a second `eOnePass == ONEPASS_OFF` runs
 * only where the first one did not. A free under `x == A` is recorded as
 * such, and an arm guarded by a test on `x` that cannot hold together
 * with `x == A` does not have the object freed. Constants are told apart
 * by value where the value is known, so two names for one number are the
 * same constant (see the fail fixture); the record is dropped when `x` is
 * assigned.
 */
#include <stdlib.h>

#define REPLY_ARRAY 1
#define REPLY_SET 2
#define REPLY_MAP 3
#define REPLY_ATTRIBUTE 4
#define ONEPASS_OFF 0
enum { KIND_A, KIND_B };

struct rep {
	int type;
	int len;
	struct rep *array;
};

void inner(struct rep *r);
void use(void *p);
int cond(void);

void one_type_per_reply(struct rep *rep)
{
	if (rep->type == REPLY_ARRAY || rep->type == REPLY_SET) {
		for (int i = 0; i < rep->len; ++i)
			inner(rep->array + i);
		free(rep->array);
	}

	if (rep->type == REPLY_MAP || rep->type == REPLY_ATTRIBUTE) {
		for (int i = 0; i < rep->len; ++i)
			inner(rep->array + i * 2);
		free(rep->array);
	}
}

void same_test_twice_the_else_is_the_other_path(int eOnePass, void *pWInfo)
{
	if (eOnePass == ONEPASS_OFF) {
		if (cond())
			free(pWInfo);
	}
	use(0);
	if (eOnePass == ONEPASS_OFF) {
		use(0);
	} else {
		free(pWInfo);
	}
}

void not_equal_then_equal(int t, void *p)
{
	if (t != KIND_A)
		free(p);
	if (t == KIND_A)
		use(p);
}

void else_if_chain(int t, void *p)
{
	if (t == KIND_A) {
		free(p);
	} else if (t == KIND_B) {
		use(p);
	}
	if (t == KIND_B)
		use(p);
}
