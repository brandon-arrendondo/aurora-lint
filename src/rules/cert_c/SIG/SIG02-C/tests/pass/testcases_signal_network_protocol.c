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
#include <string.h>

volatile sig_atomic_t packet_received = 0;
volatile sig_atomic_t ack_required = 0;
volatile sig_atomic_t connection_established = 0;
volatile sig_atomic_t data_ready = 0;

typedef struct {
    int sequence_number;
    int packet_type;
    char data[64];
} network_packet_t;

network_packet_t current_packet;

void protocol_handler(int sig) {
    if (sig == SIGUSR1) {
        packet_received = 1;
        current_packet.sequence_number = 1;
        current_packet.packet_type = 1;
        strcpy(current_packet.data, "Hello Protocol");
        printf("Network packet received signal\n");
    } else if (sig == SIGUSR2) {
        ack_required = 1;
        printf("ACK required signal received\n");
    } else if (sig == SIGTERM) {
        connection_established = 1;
        printf("Connection established signal received\n");
    } else if (sig == SIGALRM) {
        data_ready = 1;
        printf("Data ready signal received\n");
    }
}

void process_network_packet() {
    printf("Processing network packet (seq: %d, type: %d)\n",
           current_packet.sequence_number, current_packet.packet_type);
    printf("Packet data: %s\n", current_packet.data);
    printf("Validating packet checksum and sequence...\n");
}

int main() {
    printf("Using signals for normal network protocol implementation\n");

    signal(SIGUSR1, protocol_handler);
    signal(SIGUSR2, protocol_handler);
    signal(SIGTERM, protocol_handler);
    signal(SIGALRM, protocol_handler);

    pid_t network_peer = fork();
    if (network_peer == 0) {
        printf("Network Peer: Starting protocol communication\n");

        sleep(1);
        printf("Network Peer: Establishing connection\n");
        kill(getppid(), SIGTERM);

        sleep(1);
        printf("Network Peer: Sending data packet\n");
        kill(getppid(), SIGUSR1);

        sleep(1);
        printf("Network Peer: Requesting acknowledgment\n");
        kill(getppid(), SIGUSR2);

        sleep(1);
        printf("Network Peer: Sending data ready signal\n");
        kill(getppid(), SIGALRM);

        exit(0);
    } else {
        printf("Network Stack: Starting protocol processing\n");
        int protocol_events = 0;

        while (protocol_events < 4) {
            pause();

            if (connection_established) {
                printf("Processing connection establishment\n");
                printf("Initializing connection state machine\n");
                connection_established = 0;
                protocol_events++;
            }

            if (packet_received) {
                process_network_packet();
                packet_received = 0;
                protocol_events++;
            }

            if (ack_required) {
                printf("Sending acknowledgment packet\n");
                printf("ACK sent for sequence %d\n", current_packet.sequence_number);
                ack_required = 0;
                protocol_events++;
            }

            if (data_ready) {
                printf("Processing ready data from peer\n");
                printf("Data transfer complete\n");
                data_ready = 0;
                protocol_events++;
            }
        }

        wait(NULL);
        printf("Network protocol processing complete\n");
    }

    return 0;
}