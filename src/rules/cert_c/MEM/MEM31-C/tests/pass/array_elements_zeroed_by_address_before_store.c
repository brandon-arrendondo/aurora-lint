/*
 * Rule: MEM31-C
 * Source: regression
 * Status: PASS - the array is zeroed through its address before any store
 *
 * hostap's driver_nl80211_event.c shape: memset(&pw, 0, sizeof(pw)) hands the
 * array's address to a call, which can write its elements but cannot make
 * pw another array. Before the store it changes nothing the loop frees.
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

int build(const struct wpabuf **bufs, unsigned int count);

int send_hlp(struct req *reqs)
{
	const unsigned int max_hlp = 20;
	struct wpabuf *hlp[max_hlp];
	unsigned int i, num_hlp = 0;
	struct req *req;
	int ret;

	memset(&hlp, 0, sizeof(hlp));

	for (req = reqs; req; req = req->next) {
		hlp[num_hlp] = wpabuf_alloc(18 + req->len);
		if (!hlp[num_hlp])
			break;
		num_hlp++;
		if (num_hlp >= max_hlp)
			break;
	}

	ret = build((const struct wpabuf **) hlp, num_hlp);
	for (i = 0; i < num_hlp; i++)
		wpabuf_free(hlp[i]);
	return ret;
}
