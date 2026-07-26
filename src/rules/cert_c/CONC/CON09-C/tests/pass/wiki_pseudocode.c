/*
 * Rule: CON09-C
 * Source: wiki
 * Status: PASS - Compliant solution
 */

/* Hazard pointers types and structure */
structure HPRecType {
  HP[K]:*Nodetype;
  Next:*HPRecType;
}
 
/* The header of the HPRec list */
HeadHPRec: *HPRecType;
/* Per-thread private variables */
rlist: listType; /* Initially empty */
rcount: integer; /* Initially 0 */

/* The retired node routine */
RetiredNode(node:*NodeType) {
  rlist.push(node);
  rcount++;
  if(rcount >= R)
    Scan(HeadHPRec);
}

/* The scan routine */
Scan(head:*HPRecType) {
  /* Stage 1: Scan HP list and insert non-null values in plist */
  plist.init();
  hprec<-head;
  while (hprec != NULL) {
    for (i<-0 to K-1) {
      hptr<-hprec^HP[i];
      if (hptr!= NULL)
        plist.insert(hptr);
    }
    hprec<-hprec^Next;
  }

  /* Stage 2: search plist */
  tmplist<-rlist.popAll();
  rcount<-0;
  node<-tmplist.pop();
  while (node != NULL) {
    if (plist.lookup(node)) {
      rlist.push(node);
      rcount++;
    }
    else {
      PrepareForReuse(node);
    }
    node<-tmplist.pop();
  }
  plist.free();
}