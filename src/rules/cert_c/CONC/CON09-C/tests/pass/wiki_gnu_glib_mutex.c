/*
 * Rule: CON09-C
 * Source: wiki
 * Status: PASS - Should NOT trigger CON09-C violation
 */

#include <threads.h>
#include <glib-object.h>

typedef struct node_s {
  void *data;
  Node *next;
} Node;

typedef struct queue_s {
  Node *head;
  Node *tail;
  mtx_t mutex;
} Queue;

Queue* queue_new(void) {
  Queue *q = g_slice_new(sizeof(Queue));
  q->head = q->tail = g_slice_new(sizeof(Node));
  return q;
}

int queue_enqueue(Queue *q, gpointer data) {
  Node *node;
  Node *tail;
  Node *next;

  /*
   * Lock the queue before accessing the contents and
   * check the return code for success.
   */
  if (thrd_success != mtx_lock(&(q->mutex))) {
    return -1;  /* Indicate failure */
  } else {
    node = g_slice_new(Node);
    node->data = data;
    node->next = NULL;

    if(q->head == NULL) {
      q->head = node;
      q->tail = node;
    } else {
      q->tail->next = node;
      q->tail = node;
    }
    /* Unlock the mutex and check the return code */
    if (thrd_success != mtx_unlock(&(queue->mutex))) {
      return -1;  /* Indicate failure */
    }
  }
  return 0;
}

gpointer queue_dequeue(Queue *q) {
  Node *node;
  Node *head;
  Node *tail;
  Node *next;
  gpointer data;

  if (thrd_success != mtx_lock(&(q->mutex)) {
    return NULL;  /* Indicate failure */
  } else {
    head = q->head;
    tail = q->tail;
    next = head->next;
    data = next->data;
    q->head = next;
    g_slice_free(Node, head);
    if (thrd_success != mtx_unlock(&(queue->mutex))) {
      return NULL;  /* Indicate failure */
    }
  }
  return data;
}