#include "traceroute.h"

void tv_sub(struct timeval *out, struct timeval *in);
void sig_alrm(int signo);
const char *icmpcode_v4(int code);
const char *icmpcode_v6(int code);
int recv_v4(int seq, struct timeval *tv);
int recv_v6(int seq, struct timeval *tv);
Sigfunc *Signal(int signo, Sigfunc *func);
Sigfunc *signal(int signo, Sigfunc *func);
char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen);
struct addrinfo *Host_serv(const char *host, const char *serv, int family, int socktype);
void traceloop(void);
void sock_set_port(SA *, socklen_t, int);
int sock_cmp_addr(const SA *, const SA *, socklen_t);
void *Calloc(size_t n, size_t size);
void err_quit(const char *fmt, ...);
int Socket(int family, int type, int protocol);
void Gettimeofday(struct timeval *tv, void *foo);
void Sendto(int fd, const void *ptr, size_t nbytes, int flags, const struct sockaddr *sa,
            socklen_t salen);
void Bind(int fd, const struct sockaddr *sa, socklen_t salen);
void Setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen);

struct proto proto_v4 = {icmpcode_v4, recv_v4, NULL,         NULL,       NULL,
                         NULL,        0,       IPPROTO_ICMP, IPPROTO_IP, IP_TTL};

struct proto proto_v6 = {icmpcode_v6, recv_v6, NULL,           NULL,         NULL,
                         NULL,        0,       IPPROTO_ICMPV6, IPPROTO_IPV6, IPV6_UNICAST_HOPS};

/* # bytes of data, following ICMP header */
int datalen   = sizeof(struct rec);
int max_ttl   = 30;
int nprobes   = 3;
int gotalarm  = 0;
u_short dport = 32768 + 666;

int main(int argc, char **argv)
{
    int c;
    struct addrinfo *ai;
    char *h;

    opterr = 0; /* don't want getopt() writing to stderr */
    while ((c = getopt(argc, argv, "m:v")) != -1) {
        switch (c) {
            case 'm':
                if ((max_ttl = atoi(optarg)) <= 1) {
                    puts("invalid -m value");
                    exit(1);
                }
                break;
            case 'v':
                verbose++;
                break;
            case '?':
                printf("unrecognized option: %c\n", c);
                exit(1);
        }
    }

    if (optind != argc - 1) {
        puts("usage: traceroute [ -m <maxttl> -v ] <hostname>");
        exit(1);
    }

    host = argv[optind];
    pid  = getpid();
    Signal(SIGALRM, sig_alrm);

    ai = Host_serv(host, NULL, 0, 0);

    h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
    printf("traceroute to %s (%s): %d hops max, %d data bytes\n",
           ai->ai_canonname ? ai->ai_canonname : h, h, max_ttl, datalen);

    /* initialize according to protocol */
    if (ai->ai_family == AF_INET) {
        pr = &proto_v4;
    } else if (ai->ai_family == AF_INET6) {
        pr = &proto_v6;
        if (IN6_IS_ADDR_V4MAPPED(&(((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr))) {
            puts("cannot ping IPv4-mapped IPv6 address");
            exit(1);
        }
    } else {
        printf("unknown address family %d\n", ai->ai_family);
        exit(1);
    }

    pr->sasend = ai->ai_addr; /* contains destination address */
    pr->sarecv = Calloc(1, ai->ai_addrlen);
    pr->salast = Calloc(1, ai->ai_addrlen);
    pr->sabind = Calloc(1, ai->ai_addrlen);
    pr->salen  = ai->ai_addrlen;

    traceloop();

    exit(0);
}

void traceloop(void)
{
    int seq, code, done;
    double rtt;
    struct rec *rec;
    struct timeval tvrecv;

    recvfd = Socket(pr->sasend->sa_family, SOCK_RAW, pr->icmpproto);
    setuid(getuid()); /* don't need special permissions anymore */

    if (pr->sasend->sa_family == AF_INET6 && verbose == 0) {
        struct icmp6_filter myfilt;
        ICMP6_FILTER_SETBLOCKALL(&myfilt);
        ICMP6_FILTER_SETPASS(ICMP6_TIME_EXCEEDED, &myfilt);
        ICMP6_FILTER_SETPASS(ICMP6_DST_UNREACH, &myfilt);
        setsockopt(recvfd, IPPROTO_IPV6, ICMP6_FILTER, &myfilt, sizeof(myfilt));
    }

    sendfd = Socket(pr->sasend->sa_family, SOCK_DGRAM, 0);

    pr->sabind->sa_family = pr->sasend->sa_family;
    sport                 = (getpid() & 0xffff) | 0x8000; /* our source UDP port # */
    sock_set_port(pr->sabind, pr->salen, htons(sport));
    Bind(sendfd, pr->sabind, pr->salen);

    sig_alrm(SIGALRM);

    seq  = 0;
    done = 0;
    for (ttl = 1; ttl <= max_ttl && done == 0; ttl++) {
        Setsockopt(sendfd, pr->ttllevel, pr->ttloptname, &ttl, sizeof(int));
        bzero(pr->salast, pr->salen);

        printf("%2d ", ttl);
        fflush(stdout);

        for (probe = 0; probe < nprobes; probe++) {
            rec          = (struct rec *)sendbuf;
            rec->rec_seq = ++seq;
            rec->rec_ttl = ttl;
            Gettimeofday(&rec->rec_tv, NULL);

            sock_set_port(pr->sasend, pr->salen, htons(dport + seq));
            Sendto(sendfd, sendbuf, datalen, 0, pr->sasend, pr->salen);

            if ((code = (*pr->recv)(seq, &tvrecv)) == -3)
                printf(" *"); /* timeout, no reply */
            else {
                char str[NI_MAXHOST];

                if (sock_cmp_addr(pr->sarecv, pr->salast, pr->salen) != 0) {
                    if (getnameinfo(pr->sarecv, pr->salen, str, sizeof(str), NULL, 0, 0) == 0)
                        printf(" %s (%s)", str, Sock_ntop_host(pr->sarecv, pr->salen));
                    else
                        printf(" %s", Sock_ntop_host(pr->sarecv, pr->salen));
                    memcpy(pr->salast, pr->sarecv, pr->salen);
                }
                tv_sub(&tvrecv, &rec->rec_tv);
                rtt = tvrecv.tv_sec * 1000.0 + tvrecv.tv_usec / 1000.0;
                printf("  %.3f ms", rtt);

                if (code == -1) /* port unreachable; at destination */
                    done++;
                else if (code >= 0)
                    printf(" (ICMP %s)", (*pr->icmpcode)(code));
            }
            fflush(stdout);
        }
        printf("\n");
    }
}

int recv_v4(int seq, struct timeval *tv)
{
    int hlen1, hlen2, icmplen, ret;
    socklen_t len;
    ssize_t n;
    struct ip *ip, *hip;
    struct icmp *icmp;
    struct udphdr *udp;

    gotalarm = 0;
    alarm(3);
    for (;;) {
        if (gotalarm)
            return (-3); /* alarm expired */
        len = pr->salen;
        n   = recvfrom(recvfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            else
                err_quit("recvfrom error");
        }

        ip    = (struct ip *)recvbuf; /* start of IP header */
        hlen1 = ip->ip_hl << 2;       /* length of IP header */

        icmp = (struct icmp *)(recvbuf + hlen1); /* start of ICMP header */
        if ((icmplen = n - hlen1) < 8)
            continue; /* not enough to look at ICMP header */

        if (icmp->icmp_type == ICMP_TIMXCEED && icmp->icmp_code == ICMP_TIMXCEED_INTRANS) {
            if (icmplen < 8 + sizeof(struct ip))
                continue; /* not enough data to look at inner IP */

            hip   = (struct ip *)(recvbuf + hlen1 + 8);
            hlen2 = hip->ip_hl << 2;
            if (icmplen < 8 + hlen2 + 4)
                continue; /* not enough data to look at UDP ports */

            udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);
            if (hip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sport) &&
                udp->uh_dport == htons(dport + seq)) {
                ret = -2; /* we hit an intermediate router */
                break;
            }

        } else if (icmp->icmp_type == ICMP_UNREACH) {
            if (icmplen < 8 + sizeof(struct ip))
                continue; /* not enough data to look at inner IP */

            hip   = (struct ip *)(recvbuf + hlen1 + 8);
            hlen2 = hip->ip_hl << 2;
            if (icmplen < 8 + hlen2 + 4)
                continue; /* not enough data to look at UDP ports */

            udp = (struct udphdr *)(recvbuf + hlen1 + 8 + hlen2);
            if (hip->ip_p == IPPROTO_UDP && udp->uh_sport == htons(sport) &&
                udp->uh_dport == htons(dport + seq)) {
                if (icmp->icmp_code == ICMP_UNREACH_PORT)
                    ret = -1; /* have reached destination */
                else
                    ret = icmp->icmp_code; /* 0, 1, 2, ... */
                break;
            }
        }
        if (verbose) {
            printf(" (from %s: type = %d, code = %d)\n", Sock_ntop_host(pr->sarecv, pr->salen),
                   icmp->icmp_type, icmp->icmp_code);
        }
        /* Some other ICMP error, recvfrom() again */
    }
    alarm(0);               /* don't leave alarm running */
    Gettimeofday(tv, NULL); /* get time of packet arrival */
    return (ret);
}

int recv_v6(int seq, struct timeval *tv)
{
    int hlen2, icmp6len, ret;
    ssize_t n;
    socklen_t len;
    struct ip6_hdr *hip6;
    struct icmp6_hdr *icmp6;
    struct udphdr *udp;

    gotalarm = 0;
    alarm(3);
    for (;;) {
        if (gotalarm)
            return (-3); /* alarm expired */
        len = pr->salen;
        n   = recvfrom(recvfd, recvbuf, sizeof(recvbuf), 0, pr->sarecv, &len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            else
                err_quit("recvfrom error");
        }

        icmp6 = (struct icmp6_hdr *)recvbuf; /* ICMP header */
        if ((icmp6len = n) < 8)
            continue; /* not enough to look at ICMP header */

        if (icmp6->icmp6_type == ICMP6_TIME_EXCEEDED &&
            icmp6->icmp6_code == ICMP6_TIME_EXCEED_TRANSIT) {
            if (icmp6len < 8 + sizeof(struct ip6_hdr) + 4)
                continue; /* not enough data to look at inner header */

            hip6  = (struct ip6_hdr *)(recvbuf + 8);
            hlen2 = sizeof(struct ip6_hdr);
            udp   = (struct udphdr *)(recvbuf + 8 + hlen2);
            if (hip6->ip6_nxt == IPPROTO_UDP && udp->uh_sport == htons(sport) &&
                udp->uh_dport == htons(dport + seq))
                ret = -2; /* we hit an intermediate router */
            break;

        } else if (icmp6->icmp6_type == ICMP6_DST_UNREACH) {
            if (icmp6len < 8 + sizeof(struct ip6_hdr) + 4)
                continue; /* not enough data to look at inner header */

            hip6  = (struct ip6_hdr *)(recvbuf + 8);
            hlen2 = sizeof(struct ip6_hdr);
            udp   = (struct udphdr *)(recvbuf + 8 + hlen2);
            if (hip6->ip6_nxt == IPPROTO_UDP && udp->uh_sport == htons(sport) &&
                udp->uh_dport == htons(dport + seq)) {
                if (icmp6->icmp6_code == ICMP6_DST_UNREACH_NOPORT)
                    ret = -1; /* have reached destination */
                else
                    ret = icmp6->icmp6_code; /* 0, 1, 2, ... */
                break;
            }
        } else if (verbose) {
            printf(" (from %s: type = %d, code = %d)\n", Sock_ntop_host(pr->sarecv, pr->salen),
                   icmp6->icmp6_type, icmp6->icmp6_code);
        }
        /* Some other ICMP error, recvfrom() again */
    }
    alarm(0);               /* don't leave alarm running */
    Gettimeofday(tv, NULL); /* get time of packet arrival */
    return (ret);
}

Sigfunc *signal(int signo, Sigfunc *func)
{
    struct sigaction act, oact;

    act.sa_handler = func;
    sigemptyset(&act.sa_mask);
    act.sa_flags = 0;
    if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
        act.sa_flags |= SA_INTERRUPT; /* SunOS 4.x */
#endif
    } else {
#ifdef SA_RESTART
        act.sa_flags |= SA_RESTART; /* SVR4, 44BSD */
#endif
    }
    if (sigaction(signo, &act, &oact) < 0) {
        return (SIG_ERR);
    }
    return (oact.sa_handler);
}

Sigfunc *Signal(int signo, Sigfunc *func) /* for our signal() function */
{
    Sigfunc *sigfunc;

    if ((sigfunc = signal(signo, func)) == SIG_ERR) {
        puts("signal error");
    }
    return (sigfunc);
}

struct addrinfo *host_serv(const char *host, const char *serv, int family, int socktype)
{
    int n;
    struct addrinfo hints, *res;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags    = AI_CANONNAME; /* always return canonical name */
    hints.ai_family   = family;       /* AF_UNSPEC, AF_INET, AF_INET6, etc. */
    hints.ai_socktype = socktype;     /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

    if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
        return (NULL);
    }

    return (res); /* return pointer to first on linked list */
}

/*
 * There is no easy way to pass back the integer return code from
 * getaddrinfo() in the function above, short of adding another argument
 * that is a pointer, so the easiest way to provide the wrapper function
 * is just to duplicate the simple function as we do here.
 */
struct addrinfo *Host_serv(const char *host, const char *serv, int family, int socktype)
{
    int n;
    struct addrinfo hints, *res;

    bzero(&hints, sizeof(struct addrinfo));
    hints.ai_flags    = AI_CANONNAME; /* always return canonical name */
    hints.ai_family   = family;       /* 0, AF_INET, AF_INET6, etc. */
    hints.ai_socktype = socktype;     /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */

    if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
        printf("host_serv error for %s, %s: %s", (host == NULL) ? "(no hostname)" : host,
               (serv == NULL) ? "(no service name)" : serv, gai_strerror(n));
        exit(1);
    }

    return (res); /* return pointer to first on linked list */
}

char *sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    static char str[128]; /* Unix domain is largest */

    switch (sa->sa_family) {
        case AF_INET:
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)sa;

                if (inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str)) == NULL) {
                    return (NULL);
                }
                return (str);
            }

        case AF_INET6:
            {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

                if (inet_ntop(AF_INET6, &sin6->sin6_addr, str, sizeof(str)) == NULL) {
                    return (NULL);
                }
                return (str);
            }

        case AF_UNIX:
            {
                struct sockaddr_un *unp = (struct sockaddr_un *)sa;
                if (unp->sun_path[0] == 0) {
                    strcpy(str, "(no pathname bound)");
                } else {
                    snprintf(str, sizeof(str), "%s", unp->sun_path);
                }
                return (str);
            }

#ifdef HAVE_SOCKADDR_DL_STRUCT
        case AF_LINK:
            {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)sa;

                if (sdl->sdl_nlen > 0) {
                    snprintf(str, sizeof(str), "%*s", sdl->sdl_nlen, &sdl->sdl_data[0]);
                } else {
                    snprintf(str, sizeof(str), "AF_LINK, index=%d", sdl->sdl_index);
                }
                return (str);
            }
#endif
        default:
            snprintf(str, sizeof(str), "sock_ntop_host: unknown AF_xxx: %d, len %d", sa->sa_family,
                     salen);
            return (str);
    }
    return (NULL);
}

char *Sock_ntop_host(const struct sockaddr *sa, socklen_t salen)
{
    char *ptr;

    if ((ptr = sock_ntop_host(sa, salen)) == NULL) {
        puts("sock_ntop_host error"); /* inet_ntop() sets errno */
    }
    return (ptr);
}

void sock_set_port(struct sockaddr *sa, socklen_t salen, int port)
{
    if (!salen) {
        return;
    }

    switch (sa->sa_family) {
        case AF_INET:
            {
                struct sockaddr_in *sin = (struct sockaddr_in *)sa;
                sin->sin_port           = port;
                return;
            }
        case AF_INET6:
            {
                struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;
                sin6->sin6_port           = port;
                return;
            }
    }

    return;
}

int sock_cmp_addr(const struct sockaddr *sa1, const struct sockaddr *sa2, socklen_t salen)
{
    if (!salen) {
        return (-1);
    }

    if (sa1->sa_family != sa2->sa_family) {
        return (-1);
    }

    switch (sa1->sa_family) {
        case AF_INET:
            {
                return (memcmp(&((struct sockaddr_in *)sa1)->sin_addr,
                               &((struct sockaddr_in *)sa2)->sin_addr, sizeof(struct in_addr)));
            }

        case AF_INET6:
            {
                return (memcmp(&((struct sockaddr_in6 *)sa1)->sin6_addr,
                               &((struct sockaddr_in6 *)sa2)->sin6_addr, sizeof(struct in6_addr)));
            }

        case AF_UNIX:
            {
                return (strcmp(((struct sockaddr_un *)sa1)->sun_path,
                               ((struct sockaddr_un *)sa2)->sun_path));
            }
    }
    return (-1);
}

const char *icmpcode_v4(int code)
{
    switch (code) {
        case 0:
            return ("network unreachable");
        case 1:
            return ("host unreachable");
        case 2:
            return ("protocol unreachable");
        case 3:
            return ("port unreachable");
        case 4:
            return ("fragmentation required but DF bit set");
        case 5:
            return ("source route failed");
        case 6:
            return ("destination network unknown");
        case 7:
            return ("destination host unknown");
        case 8:
            return ("source host isolated (obsolete)");
        case 9:
            return ("destination network administratively prohibited");
        case 10:
            return ("destination host administratively prohibited");
        case 11:
            return ("network unreachable for TOS");
        case 12:
            return ("host unreachable for TOS");
        case 13:
            return ("communication administratively prohibited by filtering");
        case 14:
            return ("host recedence violation");
        case 15:
            return ("precedence cutoff in effect");
        default:
            return ("[unknown code]");
    }
}

const char *icmpcode_v6(int code)
{
    switch (code) {
        case ICMP6_DST_UNREACH_NOROUTE:
            return ("no route to host");
        case ICMP6_DST_UNREACH_ADMIN:
            return ("administratively prohibited");
        case ICMP6_DST_UNREACH_ADDR:
            return ("address unreachable");
        case ICMP6_DST_UNREACH_NOPORT:
            return ("port unreachable");
        default:
            return ("[unknown code]");
    }
}

void err_quit(const char *fmt, ...)
{
    va_list ap;
    char buf[MAXLINE + 1];

    va_start(ap, fmt);

    vsnprintf(buf, MAXLINE, fmt, ap);

    strcat(buf, "\n");
    fflush(stdout);
    fputs(buf, stderr);
    fflush(stderr);

    va_end(ap);

    exit(1);
}

void *Calloc(size_t n, size_t size)
{
    void *ptr;

    if ((ptr = calloc(n, size)) == NULL)
        err_quit("calloc error");
    return (ptr);
}

void tv_sub(struct timeval *out, struct timeval *in)
{
    if ((out->tv_usec -= in->tv_usec) < 0) { /* out -= in */
        --out->tv_sec;
        out->tv_usec += 1000000;
    }
    out->tv_sec -= in->tv_sec;
}

int Socket(int family, int type, int protocol)
{
    int n;

    if ((n = socket(family, type, protocol)) < 0)
        err_quit("socket error");
    return (n);
}

void Sendto(int fd, const void *ptr, size_t nbytes, int flags, const struct sockaddr *sa,
            socklen_t salen)
{
    if (sendto(fd, ptr, nbytes, flags, sa, salen) != (ssize_t)nbytes) {
        err_quit("sendto error");
    }
}

void Bind(int fd, const struct sockaddr *sa, socklen_t salen)
{
    if (bind(fd, sa, salen) < 0)
        err_quit("bind error");
}

void Setsockopt(int fd, int level, int optname, const void *optval, socklen_t optlen)
{
    if (setsockopt(fd, level, optname, optval, optlen) < 0)
        err_quit("setsockopt error");
}

void Gettimeofday(struct timeval *tv, void *foo)
{
    if (gettimeofday(tv, foo) == -1)
        err_quit("gettimeofday error");
    return;
}

void sig_alrm(int signo)
{
    if (signo) {
        // nothing to do here
    }

    gotalarm = 1;

    // just interrupt the recvfrom()
    return;
}
