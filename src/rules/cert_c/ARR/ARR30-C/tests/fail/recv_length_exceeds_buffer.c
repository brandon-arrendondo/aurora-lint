/*
 * Rule: ARR30-C
 * Source: testcases
 * Status: FAIL - Should trigger ARR30-C violation
 */

/*
 * Rule: ARR30-C - Do not form or use out-of-bounds pointers or array subscripts
 * Status: FAIL
 * Reason: recv()'s own length argument (BUFFER_SIZE + 10) exceeds
 * inputBuffer's actual size (BUFFER_SIZE), so the recv()-return-value
 * bounded-index proof (task 434) must NOT apply here -- recvResult can
 * legitimately reach a value past the end of inputBuffer, and nothing else
 * guards the index.
 */

#include <sys/socket.h>

#define BUFFER_SIZE 10

void read_into_buffer(int sock)
{
    char inputBuffer[BUFFER_SIZE];
    int recvResult;

    recvResult = recv(sock, inputBuffer, BUFFER_SIZE + 10, 0);
    if (recvResult <= 0)
    {
        return;
    }
    inputBuffer[recvResult] = '\0';
}
