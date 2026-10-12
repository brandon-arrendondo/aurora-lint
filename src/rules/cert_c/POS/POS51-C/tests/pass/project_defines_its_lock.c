/*
 * Rule: POS51-C
 * Source: testcases
 * Status: PASS - Should NOT trigger POS51-C violation
 *
 * The program defines its own pthread_mutex_lock(), a no-op shim for a
 * single-threaded build, so the calls do not acquire a POSIX mutex.
 */

typedef struct { int unused; } pthread_mutex_t;

int pthread_mutex_lock(pthread_mutex_t *m) {
    (void)m;
    return 0;
}

typedef struct {
    pthread_mutex_t balance_mutex;
    int balance;
} bank_account;

void transfer(bank_account *from, bank_account *to, int amount) {
    pthread_mutex_lock(&(from->balance_mutex));
    pthread_mutex_lock(&(to->balance_mutex));
    from->balance -= amount;
    to->balance += amount;
}
