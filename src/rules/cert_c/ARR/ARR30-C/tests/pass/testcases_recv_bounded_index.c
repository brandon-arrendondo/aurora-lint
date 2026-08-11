/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: PASS - Should NOT trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: PASS
 * Reason: recvResult is the return value of recv(sock, inputBuffer,
 * BUFFER_SIZE - 1, 0) -- a call whose length argument was given against
 * this exact buffer. recv()'s return value can never exceed that length
 * argument, so inputBuffer[recvResult] is safe by construction even
 * though no runtime bounds check guards the index itself (task 434).
 * Modeled on the Juliet CWE-789/121/122/124/126/127 socket
 * connect/listen boilerplate this pattern is shared by verbatim.
 */

#include <sys/socket.h>

#define BUFFER_SIZE 100

void read_into_buffer(int sock)
{
    char inputBuffer[BUFFER_SIZE];
    int recvResult;

    do
    {
        recvResult = recv(sock, inputBuffer, BUFFER_SIZE - 1, 0);
        if (recvResult <= 0)
        {
            break;
        }
        inputBuffer[recvResult] = '\0';
    }
    while (0);
}
