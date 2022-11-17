#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define BUFSIZE 1500
#define MAXLINE 4096    /* max text line length */
#define MAXSOCKADDR 128 /* max socket address structure size */
#define BUFFSIZE 8192   /* buffer size for reads and writes */

#define SA struct sockaddr
typedef void Sigfunc(int); /* for signal handlers */

struct rec {               /* format of outgoing UDP data */
    u_short rec_seq;       /* sequence number */
    u_short rec_ttl;       /* TTL packet left with */
    struct timeval rec_tv; /* time packet left */
};

// globals
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

char *host;
u_short sport;
int nsent; /* add 1 for each sendto() */
pid_t pid; /* our PID */
int probe;
int sendfd, recvfd; /* send on UDP sock, read on raw ICMP sock */
int ttl;
int verbose;

struct proto {
    const char *(*icmpcode)(int);
    int (*recv)(int, struct timeval *);
    struct sockaddr *sasend; /* sockaddr{} for send, from getaddrinfo */
    struct sockaddr *sarecv; /* sockaddr{} for receiving */
    struct sockaddr *salast; /* last sockaddr{} for receiving */
    struct sockaddr *sabind; /* sockaddr{} for binding source port */
    socklen_t salen;         /* length of sockaddr{}s */
    int icmpproto;           /* IPPROTO_xxx value for ICMP */
    int ttllevel;            /* setsockopt() level to set TTL */
    int ttloptname;          /* setsockopt() name to set TTL */
} * pr;

#include "icmpv6.h"
#include "ipv6.h"

#endif // TRACEROUTE_H
