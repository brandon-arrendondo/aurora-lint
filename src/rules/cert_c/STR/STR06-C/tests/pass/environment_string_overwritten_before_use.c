/*
 * Rule: STR06-C
 * Source: custom
 * Status: PASS - Should NOT trigger STR06-C violation
 * Description: An overwrite of the tokenized object ends the hazard
 * (STR06-C/2026-10-07/2): pointing the variable at another buffer, or copying
 * into it, before it is read again. A same-named variable in another function
 * that never held an environment string is not the tokenized object.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void repoint_then_read(char *other) {
    char *path = getenv("PATH");
    strtok(path, ":");
    path = other;
    puts(path);
}

void copy_into_then_read(const char *fresh) {
    char *home = getenv("HOME");
    strtok(home, "/");
    strcpy(home, fresh);
    puts(home);
}

void parameter_named_path(char *path) {
    strtok(path, ":");
    puts(path);
}
