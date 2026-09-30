/*
 * Rule: ERR33-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ERR33-C violation
 */

/*
 * Rule: ERR33-C - Detect and handle standard library errors
 * Status: PASS
 * Reason: strstr's result is tested on the next line. The test is found
 *         only if the function is read as one: the if condition before it,
 *         and a while condition later in the file, each pick an operand
 *         with #if/#else inside the parentheses.
 */

#include <string.h>

int check_groups(int a, int b);
int next_option(int argc, char **argv);
int next_option_long(int argc, char **argv, int *index);

int login(int uid, const char *dir)
{
    const char *home;

    if (
#if defined(WITH_LDAP) || defined(WITH_MYSQL)
        check_groups(uid, 0) != 0
#else
        check_groups(uid, 1) != 0
#endif
        ) {
        return -1;
    }
    home = strstr(dir, "/./");
    if (home != NULL) {
        return 1;
    }
    return 0;
}

int parse(int argc, char **argv)
{
    int option;
    int index = 0;

    while ((option =
#ifndef NO_GETOPT_LONG
            next_option_long(argc, argv, &index)
#else
            next_option(argc, argv)
#endif
            ) != -1) {
        if (option == 'h') {
            return 1;
        }
    }
    return 0;
}
