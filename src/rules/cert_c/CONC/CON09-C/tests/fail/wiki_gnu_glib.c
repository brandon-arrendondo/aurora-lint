/*
 * Rule: CON09-C
 * Source: wiki
 * Status: FAIL - Should trigger CON09-C violation
 */

#include <glib.h>
#include <glib-object.h>

typedef struct node_s {
  void *data;
  Node *next;
} Node;

typedef struct queue_s {
  Node *head;
  Node *tail;
} Queue;

Queue* queue_new(void) {
  Queue *q = g_slice_new(sizeof(Queue));
  q->head = q->tail = g_slice_new(sizeof(Node));
  return q;
}

void queue_enqueue(Queue *q, gpointer data) {
  Node *node;
  Node *tail;
  Node *next;

  node = g_slice_new(Node);
  node->data = data;
  node->next = NULL;
  while (TRUE) {
    tail = q->tail;
    next = tail->next;
    if (tail != q->tail) {
      continue;
    }
    if (next != NULL) {
      CAS(&q->tail, tail, next);
      continue;
    }
    if (CAS(&tail->next, NULL, node)) {
      break;
    }
  }
  CAS(&q->tail, tail, node);
}

gpointer queue_dequeue(Queue *q) {
  Node *node;
  Node *head;
  Node *tail;
  Node *next;
  gpointer data;

  while (TRUE) {
    head = q->head;
    tail = q->tail;
    next = head->next;
    if (head != q->head) {
      continue;
    }
    if (next == NULL) {
      return NULL; /* Empty */
    }
    if (head == tail) {
      CAS(&q->tail, tail, next);
      continue;
    }
    data = next->data;
    if (CAS(&q->head, head, next)) {
      break;
    }
  }
  g_slice_free(Node, head);
  return data;
}