/*
 * Rule: MSC12-C
 * Status: PASS - an `if` condition whose last conjunct is chosen by
 *         conditional compilation, so the comparison reads as a bare
 *         statement with a synthesized `;` (pure-ftpd's upload-pipe uid
 *         checks). Reporting it as a `==`-for-`=` typo describes the parse,
 *         not the code.
 */

#include <sys/stat.h>
#include <unistd.h>

int check_owner(const struct stat *st)
{
    if ((st->st_mode & 0777) != 0600 ||
#ifdef SQC_TEST_NON_ROOT
        st->st_uid != geteuid()
#else
        st->st_uid != (uid_t) 0
#endif
        ) {
        return -1;
    }
    return 0;
}
