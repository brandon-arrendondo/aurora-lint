/*
 * Rule: MEM30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger MEM30-C violation
 */

/*
 * Rule: MEM30-C - Do not access freed memory
 * Status: PASS
 * Reason: A realloc self-assignment onto a struct field
 *         (cfg->topics = realloc(cfg->topics, n)) stores the result back into
 *         the same field, so the field is valid (modulo the null check) and the
 *         later cfg->topics[i] write is NOT a use-after-free.
 *         Mirrors the mosquitto client_shared.c false positive (task 198).
 */

#include <stdlib.h>
#include <string.h>

struct config {
    char **topics;
    int topic_count;
};

int add_topic(struct config *cfg, const char *topic) {
    cfg->topics = realloc(cfg->topics, (cfg->topic_count + 1) * sizeof(char *));
    if (!cfg->topics) {
        return -1;
    }
    cfg->topics[cfg->topic_count] = strdup(topic);
    cfg->topic_count++;
    return 0;
}

/* Nested field path self-assign (im->clip->list pattern) must stay clean. */
struct clip {
    int *list;
    int count;
};
struct image {
    struct clip *clip;
};

int add_clip(struct image *im, int v) {
    im->clip->list = realloc(im->clip->list, (im->clip->count + 1) * sizeof(int));
    if (im->clip->list == NULL) {
        return -1;
    }
    im->clip->list[im->clip->count] = v;
    im->clip->count++;
    return 0;
}

/* Plain-variable self-assign form must also stay clean. */
int grow(int n) {
    int *buf = malloc(n * sizeof(int));
    buf = realloc(buf, 2 * n * sizeof(int));
    if (buf == NULL) {
        return -1;
    }
    buf[0] = 1;
    free(buf);
    return 0;
}
