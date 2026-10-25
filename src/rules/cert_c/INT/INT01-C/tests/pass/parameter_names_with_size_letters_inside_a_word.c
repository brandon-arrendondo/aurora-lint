/*
 * Rule: INT01-C
 * Source: aurora-lint
 * Status: PASS - parameters named for no size, or not of an integer type
 *
 * filename and fileName hold "len" only inside another word, silent holds
 * it inside one, and the array bound KEY_SIZE belongs to the type, not to
 * the name key. pCount and getlen are named for a size, but a void pointer
 * and a function pointer hold none, nor does a struct pointer or a string.
 * country begins with "count" without being that word, and account,
 * discount and resize are ordinary words a size word only ends.
 */
#define KEY_SIZE 16

struct counters { int total; };

int open_file(const char *filename, int silent);
void load_font(const char *fileName, float spacing);
void set_key(unsigned char key[KEY_SIZE]);
void tally(struct counters *count);
void reset(void *pCount);
void measure(int (*getlen)(const char *));
void label(const char *size_label, char *lenbuf);

/* "count" begins country without being its word. */
typedef unsigned char u8;
void set_country(int country_id, u8 band);

/* Ordinary words that a size word only ends. */
void post_charge(int account, int discount, int account_id, int resize);
