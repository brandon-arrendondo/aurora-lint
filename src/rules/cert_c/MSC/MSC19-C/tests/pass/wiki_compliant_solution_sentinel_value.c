/*
 * Rule: MSC19-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

#include <stdio.h>
#include <stdint.h>
#include <malloc.h>

enum { FINAL_ITEM=SIZE_MAX, INV_SIZE=20 };

size_t *arraySort(size_t *array);

int main(void) {
  size_t i;
  size_t stockOfItem[INV_SIZE];
  size_t *sortedArray;


  /* Other code that might use stockarray but leaves it empty */

  sortedArray = arraySort(stockOfItem);
  
  for (i = 0; sortedArray[i] != FINAL_ITEM; i++) {
    printf("Item stock: %zd", sortedArray[i]);
  }
  
  return 0;
}

/* Create new sorted array */
size_t *arraySort(size_t *array) {
  size_t i;
  size_t *sortedArray;

  for(i = 0; array[i] != FINAL_ITEM; i++);

  if (i == 0) {
    size_t *emptyArray = (size_t*) malloc(sizeof(size_t));
    if(emptyArray == NULL) {
      /* Handle memory error */
    }
    emptyArray[0] = FINAL_ITEM;
    return emptyArray;
  }
  
  sortedArray = (size_t*) malloc(sizeof(size_t)*i);
  if (sortedArray == NULL) {
    /* Handle memory error */
  }

  /* Add sorted data to array */

  return sortedArray;
 }