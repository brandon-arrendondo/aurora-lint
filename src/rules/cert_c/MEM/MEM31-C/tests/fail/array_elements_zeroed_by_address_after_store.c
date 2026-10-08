/*
 * Rule: MEM31-C
 * Source: regression
 * Status: FAIL - the array is zeroed through its address after the store
 *
 * memset(&hlp, ...) between the store and the freeing loop clears the stored
 * pointer, so the loop frees nothing and the block leaks.
 */
#include <stdlib.h>
#include <string.h>

struct wpabuf {
	size_t size;
	unsigned char *buf;
};

struct wpabuf *wpabuf_alloc(size_t len)
{
	struct wpabuf *b = calloc(1, sizeof(*b) + len);
	if (b == NULL)
		return NULL;
	b->size = len;
	b->buf = (unsigned char *) (b + 1);
	return b;
}

void wpabuf_free(struct wpabuf *b)
{
	free(b);
}

struct req {
	struct req *next;
	size_t len;
};

int build(const struct wpabuf **bufs, unsigned int count)
{
	size_t total = 0;
	unsigned int i;

	for (i = 0; i < count; i++)
		total += bufs[i]->size;
	return (int) total;
}

int send_hlp(struct req *reqs)
{
	const unsigned int max_hlp = 20;
	struct wpabuf *hlp[max_hlp];
	unsigned int i, num_hlp = 0;
	struct req *req;
	int ret;

	for (req = reqs; req; req = req->next) {
		hlp[num_hlp] = wpabuf_alloc(18 + req->len);
		if (!hlp[num_hlp])
			break;
		num_hlp++;
		if (num_hlp >= max_hlp)
			break;
	}

	memset(&hlp, 0, sizeof(hlp));
	ret = build((const struct wpabuf **) hlp, num_hlp);
	for (i = 0; i < num_hlp; i++)
		wpabuf_free(hlp[i]);
	return ret;
}
