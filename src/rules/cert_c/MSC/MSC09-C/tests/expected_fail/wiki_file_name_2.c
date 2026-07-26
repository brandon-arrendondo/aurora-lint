/*
 * Rule: MSC09-C
 * Source: wiki
 * Status: EXPECTED FAIL - Known limitation: MSC09-C only flags raw
 * non-ASCII bytes/escapes in literals. This example's violation is instead
 * "reads a filename from stdin with no validation against the portable
 * character set before use" -- a data-flow pattern (external input reaching
 * a downstream use unguarded by a strcspn/strspn-style character-class
 * check) that would require naming heuristics or taint tracking too
 * fragile/narrow to implement safely as a general check.
 */

char myFilename[1000];
const char elimNewLn[] = "\n";

fgets(myFilename, sizeof(myFilename)-1, stdin);
myFilename[sizeof(myFilename)-1] = '\0';
myFilename[strcspn(myFilename, elimNewLn)] = '\0';