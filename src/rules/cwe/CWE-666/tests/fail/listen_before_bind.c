/*
 * Rule: CWE-666
 * Status: FAIL - listen() called before bind()
 */

int socket(int domain, int type, int protocol);
int bind(int sockfd, const void *addr, unsigned int addrlen);
int listen(int sockfd, int backlog);

void f(void) {
    int sock = socket(2, 1, 0);
    listen(sock, 5);  /* VIOLATION: listen before bind */
    bind(sock, 0, 0);
}
