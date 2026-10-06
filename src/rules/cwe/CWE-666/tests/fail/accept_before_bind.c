/*
 * Rule: CWE-666
 * Status: FAIL - accept() called before bind()
 */

int socket(int domain, int type, int protocol);
int bind(int sockfd, const void *addr, unsigned int addrlen);
int listen(int sockfd, int backlog);
int accept(int sockfd, void *addr, unsigned int *addrlen);

void f(void) {
    int sock = socket(2, 1, 0);
    int client = accept(sock, 0, 0);  /* VIOLATION: accept before bind */
    bind(sock, 0, 0);
    listen(sock, 5);
}
