/*
 * Rule: API03-C
 * Source: wiki
 * Status: PASS - Should NOT trigger API03-C violation
 */

/* Initialization of pthread attribute objects */
int pthread_condattr_init(pthread_condattr_t *);
int pthread_mutexattr_init(pthread_mutexattr_t *);
int pthread_rwlockattr_init(pthread_rwlockattr_t *);

/* Initialization of pthread objects using attributes */
int pthread_cond_init(pthread_cond_t * restrict, const pthread_condattr_t * restrict);
int pthread_mutex_init(pthread_mutex_t * restrict, const pthread_mutexattr_t * restrict);
int pthread_rwlock_init(pthread_rwlock_t * restrict, const pthread_rwlockattr_t * restrict);