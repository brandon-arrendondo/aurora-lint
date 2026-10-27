/*
 * Rule: DCL37-C
 * Status: PASS - a specifier that only names a tag, without a body and not
 * standing alone, is not where the tag is declared, and a tag declared in a
 * block has block scope, where an underscore followed by a lowercase letter
 * is not reserved.
 */

struct _ext_tag *lookup(const char *key);

int count_items(void) {
  struct _local {
    int value;
  } item = {0};
  union _bits;
  return item.value;
}
