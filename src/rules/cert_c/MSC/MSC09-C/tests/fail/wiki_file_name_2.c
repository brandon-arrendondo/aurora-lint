/*
 * Rule: MSC09-C
 * Source: wiki
 * Status: FAIL - Should trigger MSC09-C violation
 */

char myFilename[1000];
const char elimNewLn[] = "\n";

fgets(myFilename, sizeof(myFilename)-1, stdin);
myFilename[sizeof(myFilename)-1] = '\0';
myFilename[strcspn(myFilename, elimNewLn)] = '\0';