/*
 * Rule: CON01-C
 * Source: thread-API families (POSIX)
 * Status: FAIL - Should trigger CON01-C violation
 *
 * CERT's noncompliant shape with POSIX threads: verify_balance releases a
 * mutex its caller acquired, so the caller's own unlock releases it twice.
 */

#include <pthread.h>

enum { MIN_BALANCE = 50 };

static pthread_mutex_t mp = PTHREAD_MUTEX_INITIALIZER;
static int account_balance;

static int verify_balance(int amount) {
    if (account_balance - amount < MIN_BALANCE) {
        pthread_mutex_unlock(&mp); /* violation */
        return -1;
    }
    return 0;
}

void debit(int amount) {
    pthread_mutex_lock(&mp);
    if (verify_balance(amount) == -1) {
        pthread_mutex_unlock(&mp);
        return;
    }
    account_balance -= amount;
    pthread_mutex_unlock(&mp);
}
