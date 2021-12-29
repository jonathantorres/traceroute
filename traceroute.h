#ifndef TRACEROUTE_H
#define TRACEROUTE_H

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <pthread.h>

#define BUFSIZE     1500
#define MAXLINE     4096    /* max text line length */
#define MAXSOCKADDR  128    /* max socket address structure size */
#define BUFFSIZE    8192    /* buffer size for reads and writes */

#define SA struct sockaddr
typedef void Sigfunc(int);   /* for signal handlers */

struct rec {               /* format of outgoing UDP data */
    u_short rec_seq;       /* sequence number */
    u_short rec_ttl;       /* TTL packet left with */
    struct timeval rec_tv; /* time packet left */
};

// globals
char recvbuf[BUFSIZE];
char sendbuf[BUFSIZE];

int     datalen;        /* #bytes of data, following ICMP header */
char    *host;
u_short sport, dport;
int     nsent;          /* add 1 for each sendto() */
pid_t   pid;            /* our PID */
int     probe, nprobes;
int     sendfd, recvfd; /* send on UDP sock, read on raw ICMP sock */
int     ttl, max_ttl;
int     verbose;

// function prototypes
char *icmpcode_v4(int);
char *icmpcode_v6(int);
int   recv_v4(int, struct timeval*);
int   recv_v6(int, struct timeval*);
void  sig_alrm(int);
void  traceloop(void);
void  tv_sub(struct timeval*, struct timeval*);

struct proto {
    char  *(*icmpcode)(int);
    int    (*recv)(int, struct timeval *);
    struct sockaddr  *sasend; /* sockaddr{} for send, from getaddrinfo */
    struct sockaddr  *sarecv; /* sockaddr{} for receiving */
    struct sockaddr  *salast; /* last sockaddr{} for receiving */
    struct sockaddr  *sabind; /* sockaddr{} for binding source port */
    socklen_t         salen;  /* length of sockaddr{}s */
    int           icmpproto;  /* IPPROTO_xxx value for ICMP */
    int      ttllevel;        /* setsockopt() level to set TTL */
    int      ttloptname;      /* setsockopt() name to set TTL */
} *pr;

#include "ipv6.h"
#include "icmpv6.h"

#endif // TRACEROUTE_H
