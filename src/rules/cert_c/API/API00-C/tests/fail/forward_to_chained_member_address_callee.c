/*
 * Rule: API00-C
 * Source: custom
 * Status: FAIL - SHOULD trigger API00-C violation
 * Description: The chained twin of forward_to_member_address_callee.c.
 * service_flush takes &wpa_s->global->services, which READS
 * wpa_s->global on the way to the address, so wpa_s is dereferenced
 * outright. A text test keyed on the `&` in front of `wpa_s->` cannot tell
 * this from a bare member address, and neither shape may drop the
 * forwarder. Both callees are static so neither is itself reported.
 */

struct list {
    struct list *next;
};

struct global {
    struct list services;
};

struct supplicant {
    struct global *global;
};

static int list_empty(const struct list *l)
{
    if (!l)
        return 1;
    return l->next == l;
}

static int service_flush(struct supplicant *wpa_s)
{
    return list_empty(&wpa_s->global->services);
}

int handler_flush_service(struct supplicant *wpa_s)
{
    return service_flush(wpa_s);
}
