/*
 * Rule: STR06-C
 * Source: custom
 * Status: FAIL - Should trigger STR06-C violation
 * Description: Each function refers to an environment string after strtok()
 * tokenized it in place: a read of the variable that holds it, an element
 * read, and a later getenv() of the same variable (STR06-C/2026-10-07/3).
 * Each finding sits at that use, not at the strtok() call.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void print_path_after_parse(void) {
    char *path = getenv("PATH");
    char *tok = strtok(path, ":");
    while (tok != NULL) {
        puts(tok);
        tok = strtok(NULL, ":");
    }
    printf("PATH: %s\n", path);
}

int first_char_after_parse(void) {
    char *home;
    home = getenv("HOME");
    strtok(home, "/");
    return home[0];
}

void getenv_again_after_parse(void) {
    strtok(getenv("PATH"), ":");
    puts(getenv("PATH"));
}
