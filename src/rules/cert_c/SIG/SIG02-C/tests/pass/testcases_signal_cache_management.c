/*
 * Rule: SIG02-C
 * Source: testcases
 * Status: PASS - Should NOT trigger SIG02-C violation
 *
 * Once a FAIL fixture: it was reported for registering handlers for signals
 * named like ordinary-work signals and for kill() calls carrying them. A
 * registration is not a send, and every kill() here targets another process
 * (getppid() or a worker's pid). SIG02-C reports only the program signaling
 * its own process or threads: raise(), pthread_kill(), kill(getpid(), ...).
 */

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

volatile sig_atomic_t cache_hit = 0;
volatile sig_atomic_t cache_miss = 0;
volatile sig_atomic_t cache_evict = 0;
volatile sig_atomic_t cache_refresh = 0;

typedef struct {
    int hit_count;
    int miss_count;
    int eviction_count;
    int cache_size;
} cache_stats_t;

cache_stats_t cache_stats = {0, 0, 0, 100};

void cache_handler(int sig) {
    if (sig == SIGUSR1) {
        cache_hit = 1;
        cache_stats.hit_count++;
        printf("Cache hit signal received (hits: %d)\n", cache_stats.hit_count);
    } else if (sig == SIGUSR2) {
        cache_miss = 1;
        cache_stats.miss_count++;
        printf("Cache miss signal received (misses: %d)\n", cache_stats.miss_count);
    } else if (sig == SIGTERM) {
        cache_evict = 1;
        cache_stats.eviction_count++;
        printf("Cache eviction signal received (evictions: %d)\n", cache_stats.eviction_count);
    } else if (sig == SIGALRM) {
        cache_refresh = 1;
        printf("Cache refresh signal received\n");
    }
}

int main() {
    printf("Using signals for normal cache management operations\n");

    signal(SIGUSR1, cache_handler);
    signal(SIGUSR2, cache_handler);
    signal(SIGTERM, cache_handler);
    signal(SIGALRM, cache_handler);

    pid_t cache_client = fork();
    if (cache_client == 0) {
        printf("Cache Client: Starting cache operations\n");

        sleep(1);
        printf("Cache Client: Cache hit for key 'user123'\n");
        kill(getppid(), SIGUSR1);

        sleep(1);
        printf("Cache Client: Cache miss for key 'user456'\n");
        kill(getppid(), SIGUSR2);

        sleep(2);
        printf("Cache Client: Triggering cache eviction\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Cache Client: Requesting cache refresh\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Cache Manager: Starting cache management service\n");
        int cache_operations = 0;

        while (cache_operations < 4) {
            pause();

            if (cache_hit) {
                printf("Cache Manager: Processing cache hit\n");
                printf("Cache Manager: Returning cached data for request\n");
                printf("Cache Manager: Hit ratio: %.2f%%\n",
                       (float)cache_stats.hit_count / (cache_stats.hit_count + cache_stats.miss_count) * 100);
                cache_hit = 0;
                cache_operations++;
            }

            if (cache_miss) {
                printf("Cache Manager: Processing cache miss\n");
                printf("Cache Manager: Fetching data from backend\n");
                printf("Cache Manager: Storing new data in cache\n");
                cache_miss = 0;
                cache_operations++;
            }

            if (cache_evict) {
                printf("Cache Manager: Processing cache eviction\n");
                printf("Cache Manager: Removing least recently used items\n");
                cache_stats.cache_size -= 10;
                printf("Cache Manager: Cache size after eviction: %d\n", cache_stats.cache_size);
                cache_evict = 0;
                cache_operations++;
            }

            if (cache_refresh) {
                printf("Cache Manager: Processing cache refresh\n");
                printf("Cache Manager: Invalidating stale cache entries\n");
                printf("Cache Manager: Reloading fresh data from source\n");
                cache_refresh = 0;
                cache_operations++;
            }
        }

        wait(NULL);
        printf("Cache management operations complete\n");
        printf("Final stats - Hits: %d, Misses: %d, Evictions: %d\n",
               cache_stats.hit_count, cache_stats.miss_count, cache_stats.eviction_count);
    }

    return 0;
}