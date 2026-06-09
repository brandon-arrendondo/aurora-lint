/*
 * Rule: SIG31-C
 * Source: testcases
 * Status: FAIL - Should trigger SIG31-C violation
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <string.h>

typedef struct {
    int thread_count;
    int active_threads[10];
    char thread_names[10][64];
    double thread_cpu_usage[10];
    int shared_resource_locks;
} thread_data_t;

thread_data_t global_thread_data = {0};
pthread_mutex_t global_mutex = PTHREAD_MUTEX_INITIALIZER;

void unsafe_handler(int sig) {
    /* Violation: Accessing thread-shared data in signal handler */
    /* This is especially dangerous as it can cause deadlocks */

    global_thread_data.thread_count++;

    /* Trying to access shared data without proper synchronization */
    for (int i = 0; i < 10; i++) {
        global_thread_data.active_threads[i] = (i < global_thread_data.thread_count) ? 1 : 0;
        sprintf(global_thread_data.thread_names[i], "signal_thread_%d", i);
        global_thread_data.thread_cpu_usage[i] += 0.1;
    }

    global_thread_data.shared_resource_locks++;

    printf("Handler: threads=%d, locks=%d, signal=%d\n",
           global_thread_data.thread_count,
           global_thread_data.shared_resource_locks, sig);
}

void* worker_thread(void* arg) {
    int thread_id = *(int*)arg;

    for (int i = 0; i < 10; i++) {
        /* Simulate thread accessing shared data */
        pthread_mutex_lock(&global_mutex);

// SQC-SUPPRESS: ARR30-C HASH:2932a358915bfa68 JUSTIFICATION: "Test fixture: suppress co-firing rule"
        global_thread_data.active_threads[thread_id] = 1;
        sprintf(global_thread_data.thread_names[thread_id], "worker_%d", thread_id);
        global_thread_data.thread_cpu_usage[thread_id] = i * 0.5;

        pthread_mutex_unlock(&global_mutex);

        usleep(50000);
    }

    return NULL;
}

int main() {
    printf("Demonstrating unsafe thread-shared data access in signal handler\n");
    printf("PID: %d\n", getpid());

    signal(SIGUSR1, unsafe_handler);

    pthread_t threads[3];
    int thread_ids[3] = {0, 1, 2};

    /* Create worker threads */
    for (int i = 0; i < 3; i++) {
        pthread_create(&threads[i], NULL, worker_thread, &thread_ids[i]);
    }

    for (int i = 0; i < 15; i++) {
        pthread_mutex_lock(&global_mutex);

        global_thread_data.thread_count = 3;
        global_thread_data.shared_resource_locks = i;

        for (int j = 0; j < 3; j++) {
            sprintf(global_thread_data.thread_names[j], "main_thread_%d", j);
            global_thread_data.thread_cpu_usage[j] = i * 0.3;
        }

        pthread_mutex_unlock(&global_mutex);

        printf("Main: threads=%d, locks=%d\n",
               global_thread_data.thread_count,
               global_thread_data.shared_resource_locks);

        usleep(200000);
    }

    /* Wait for threads to complete */
    for (int i = 0; i < 3; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
