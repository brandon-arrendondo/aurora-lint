/*
 * Rule: CWE-666
 * Status: PASS - Client socket: no accept needed
 */

int socket(int domain, int type, int protocol);
int connect(int sockfd, const void *addr, unsigned int addrlen);

void f(void) {
    int sock = socket(2, 1, 0);
    connect(sock, 0, 16);  /* Client side: connect, not bind/listen/accept */
}
