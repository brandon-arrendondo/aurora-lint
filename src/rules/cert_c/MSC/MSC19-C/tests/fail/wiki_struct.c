/*
 * Rule: MSC19-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC19-C violation
 */

#include <stdio.h>
enum { INV_SIZE=20 };

typedef struct {
  size_t stockOfItem[INV_SIZE];
  size_t length;
} Inventory;

size_t *getStock(Inventory iv);

int main(void) {
  Inventory iv;
  size_t *item;

  iv.length = 0;

  /*
   * Other code that might modify the inventory but still
   * leave no items in it upon completion.
   */

  item = getStock(iv);

  printf("Stock of first item in inventory: %zd\n", item[0]);
  
  return 0;
}

size_t *getStock(Inventory iv) {
  if (iv.length == 0) {
    return NULL;
  }
  else {
    return iv.stockOfItem;
  }
}