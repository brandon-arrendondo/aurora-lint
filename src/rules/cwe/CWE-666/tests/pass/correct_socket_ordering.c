/*
 * Rule: CWE-666
 * Status: PASS - Correct socket ordering: bind → listen → accept
 */

int socket(int domain, int type, int protocol);
int bind(int sockfd, const void *addr, unsigned int addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, void *addr, unsigned int *addrlen);

void f(void) {
    int sock = socket(2, 1, 0);
    bind(sock, 0, 16);
    listen(sock, 5);
    int client = accept(sock, 0, 0);  /* Correct order */
}
