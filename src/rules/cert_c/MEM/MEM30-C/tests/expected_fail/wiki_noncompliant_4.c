/*
 * Rule: MEM30-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: the CERT noncompliant example is
 * reported only once `gdRealloc` is declared as following realloc's contract
 * (`[environment.allocators] gdRealloc = "realloc"`, or `--allocator
 * gdRealloc=realloc`). Its body is not in the scan, and a name containing
 * "realloc" is not evidence that it releases its first argument. The
 * declared case is asserted by tests/cli_integration.rs.
 */

void gdClipSetAdd(gdImagePtr im, gdClipRectanglePtr rect) {
  gdClipRectanglePtr more;
  if (im->clip == 0) {
   /* ... */
  }
  if (im->clip->count == im->clip->max) {
    more = gdRealloc (im->clip->list,(im->clip->max + 8) *
                      sizeof (gdClipRectangle));
    /*
     * If the realloc fails, then we have not lost the
     * im->clip->list value.
     */
    if (more == 0) return; 
    im->clip->max += 8;
  }
  im->clip->list[im->clip->count] = *rect;
  im->clip->count++;

}