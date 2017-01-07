#include <assert.h>
#include <err.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <sys/errno.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#define BIND_PORT 7890

#define OPC_HOST "127.0.0.1"
#define OPC_PORT "7891"

struct client_info_t {
    int fd;
};

/* Decl for list of clients */
SLIST_HEAD(clientshead, clentry);
struct clentry {
    int				fd;
    char			addrtxt[INET6_ADDRSTRLEN];
    uint8_t			buf[65536 + 4];
    int				amt;
    SLIST_ENTRY(clentry)	entries;
};

#define NUM_CHAN	4
#define NUM_LEDS	682
uint8_t ledbuf[NUM_CHAN][NUM_LEDS * 3];
int ledbuf_dirty = 0;

static int		createlisten(int listenport, int *listensock4, int *listensock6);
static int		opcconnect(const char *host, const char *port);
static char *		get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen);
static struct clentry *	findsock(int fd, struct clientshead *head);
static void		readfromsock(int fd, struct clientshead *head, int *numclients);
static void		closesock(int fd, struct clientshead *head, int *numclients);

int
main(int argc, char **argv) {
    int listensock4, listensock6, opcsock, numfds, numlisten, numclients;
    struct pollfd *fds;
    struct clentry *clp;
    struct clientshead clients = SLIST_HEAD_INITIALIZER(clients);

    if (createlisten(BIND_PORT, &listensock4, &listensock6) != 0)
	exit(EX_OSERR);

    if ((opcsock = opcconnect(OPC_HOST, OPC_PORT)) == -1)
	exit(EX_OSERR);

    fds = NULL;
    numclients = 0;
    numlisten = 0;
    if (listensock4 != -1)
	numlisten++;
    if (listensock6 != -1)
	numlisten++;

    while (1) {
	int i, sidx;

	numfds = numclients + numlisten;
	fds = realloc(fds, sizeof(fds[0]) * numfds);
	sidx = 0;
	if (listensock4 != -1) {
	    fds[sidx].fd = listensock4;
	    fds[sidx].events = POLLRDNORM;
	    fds[sidx++].revents = 0;
	}
	if (listensock6 != -1) {
	    fds[sidx].fd = listensock6;
	    fds[sidx].events = POLLRDNORM;
	    fds[sidx++].revents = 0;
	}
	SLIST_FOREACH(clp, &clients, entries) {
	    fds[sidx].fd = clp->fd;
	    fds[sidx].events = POLLRDNORM;
	    fds[sidx++].revents = 0;
	}
	assert(numfds == sidx);
	if (poll(fds, sidx, -1) == -1) {
	    if (errno == EINTR)
		continue;
	    warn("poll failed");
	    break;
	}
	for (i = 0; i < numfds; i++) {
	    /* Slot 0 & 1 may be listen sockets, check for new connections */
	    if (i < numlisten) {
		int tmpfd;
		socklen_t addrlen;
		struct sockaddr saddr;

		if (fds[i].revents & POLLRDNORM) {
		    addrlen = sizeof(saddr);
		    memset(&saddr, 0, sizeof(saddr));
		    if ((tmpfd = accept4(fds[i].fd, &saddr, &addrlen, SOCK_NONBLOCK)) == -1) {
			warn("Unable to accept new connection");
			continue;
		    }
		    if ((clp = calloc(1, sizeof(*clp))) == NULL) {
			warnx("Can't allocate listener");
			continue;
		    }

		    clp->fd = tmpfd;
		    get_ip_str(&saddr, clp->addrtxt, sizeof(clp->addrtxt));
		    warnx("Accepted new connection from %s",
		      clp->addrtxt);
		    SLIST_INSERT_HEAD(&clients, clp, entries);
		    numclients++;
		}
		if (fds[i].revents & (POLLERR | POLLHUP)) {
		    warnx("v%s socket error", i == 0 ? "4" : "6");
		    continue;
		}
	    } else {
		/* See if our clients have anything to say */
		if (fds[i].revents & POLLRDNORM) {
		    readfromsock(fds[i].fd, &clients, &numclients);
		}
		if (fds[i].revents & (POLLERR | POLLHUP)) {
		    closesock(fds[i].fd, &clients, &numclients);
		}
	    }
	}
	if (ledbuf_dirty) {
	    uint8_t hdr[4];
	    int amt, sz;
	    struct iovec iov[2];

	    sz = NUM_CHAN * NUM_LEDS * 3;
	    hdr[0] = 0; // Channel
	    hdr[1] = 0; // Command
	    hdr[2] = sz >> 8;
	    hdr[3] = sz & 0xff;
	    iov[0].iov_base = hdr;
	    iov[0].iov_len = sizeof(hdr);
	    iov[1].iov_base = ledbuf;
	    iov[1].iov_len = sizeof(ledbuf);
	    amt = writev(opcsock, iov, 2);
	    if (amt == -1)
		err(EX_IOERR, "Error writing to OPC server");

	    if (amt != sz + 4)
		err(EX_IOERR, "Short write to OPC server (%d vs %d)", amt, sz + 4);

	    //printf("Packet sent\n");
	    ledbuf_dirty = 0;
	}
    }
}

static int
createlisten(int listenport, int *listensock4, int *listensock6)
{
    struct sockaddr_in laddr4;
    struct sockaddr_in6 laddr6;
    int one = 1;

    if ((*listensock4 = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
	warn("Unable to create IPv4 listen socket");
	return(-1);
    }
    if ((*listensock6 = socket(AF_INET6, SOCK_STREAM, 0)) == -1) {
	warn("Unable to create IPv6 listen socket");
	return(-1);
    }

    if (setsockopt (*listensock4, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
	warn("Unable to set SO_REUSEADDR on v4 socket");
    memset(&laddr4, 0, sizeof(laddr4));
    laddr4.sin_family = AF_INET;
    laddr4.sin_port = htons(listenport);
    laddr4.sin_addr.s_addr = INADDR_ANY;
    if ((bind(*listensock4, (struct sockaddr *)&laddr4, sizeof(laddr4))) == -1) {
	warn("Unable to bind to IPv4 address");
	return(-1);
    }

    if (setsockopt (*listensock6, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1)
	warn("Unable to set SO_REUSEADDR on v6 socket");
    memset(&laddr6, 0, sizeof(laddr6));
    laddr6.sin6_family = AF_INET6;
    laddr6.sin6_port = htons(listenport);
    laddr6.sin6_addr = in6addr_any;
    if ((bind(*listensock6, (struct sockaddr *)&laddr6, sizeof(laddr6))) == -1) {
	warn("Unable to bind to IPv6 address");
	return(-1);
    }
    if (listen(*listensock4, 5) < 0) {
	warn("Unable to listen to IPv4 socket");
	return(-1);
    }

    if (listen(*listensock6, 5) < 0) {
	/* If the system is set to bind v6 addresses when you bind v4 so just ignore the error */
	if (errno != EADDRINUSE) {
	    warn("Unable to listen to IPv6 socket");
	    return(-1);
	}
	close(*listensock6);
	*listensock6 = -1;
    }

    return(0);
}

/* Stolen from http://beej.us/guide/bgnet/output/html/multipage/inet_ntopman.html */
static char *
get_ip_str(const struct sockaddr *sa, char *s, size_t maxlen)
{
    switch(sa->sa_family) {
    case AF_INET:
	inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
	  s, maxlen);
	break;

    case AF_INET6:
	inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
	  s, maxlen);
	break;

    default:
	strncpy(s, "Unknown AF", maxlen);
    }

    return s;
}

/* Search the list for the fd */
static struct clentry *
findsock(int fd, struct clientshead *head)
{
	struct clentry *clp;

	SLIST_FOREACH(clp, head, entries) {
		if (clp->fd == fd)
			return(clp);
	}

	return(NULL);
}

static int
opcconnect(const char *host, const char *port) {
    int opcsock, rtn;
    struct addrinfo addrhint, *res, *res0;
    char *cause;

    memset(&addrhint, 0, sizeof(addrhint));
    addrhint.ai_family = PF_UNSPEC;
#if 1
    addrhint.ai_socktype = SOCK_STREAM;
    addrhint.ai_protocol = IPPROTO_TCP;
#else
    addrhint.ai_socktype = SOCK_DGRAM;
    addrhint.ai_protocol = IPPROTO_UDP;
#endif
    if ((rtn = getaddrinfo(host, port, &addrhint, &res0)) != 0)
	err(EX_NOHOST, "Unable to resolve host: %s", gai_strerror(rtn));

    opcsock = -1;
    for (res = res0; res; res = res->ai_next) {
	opcsock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (opcsock < 0) {
	    cause = "create socket";
	    continue;
	}

	if (connect(opcsock, res->ai_addr, res->ai_addrlen) < 0) {
	    cause = "connect";
	    close(opcsock);
	    opcsock = -1;
	    continue;
	}
	break; /* Got one */
    }
    freeaddrinfo(res0);

    if (opcsock < 0)
	err(EX_NOHOST, "Unable to %s", cause);

    return(opcsock);
}

static void
readfromsock(int fd, struct clientshead *head, int *numclients) {
    struct clentry *clp;
    int amt, r;

    clp = findsock(fd, head);
    assert(clp != NULL);
    amt = sizeof(clp->buf) - 1 - clp->amt;
    if ((r = read(fd, clp->buf + clp->amt, amt)) == -1) {
	warn("Unable to read from %s", clp->addrtxt);
	closesock(fd, head, numclients);
	return;
    }
    if (r == 0) {
	closesock(fd, head, numclients);
	return;
    }
    //printf("Read for %s got %d bytes\n", clp->addrtxt, r);
    clp->amt += r;
    if (clp->amt == sizeof(clp->buf) - 1) {
	warnx("Buffer overflow, aborting");
	closesock(fd, head, numclients);
	return;
    }

    while (clp->amt > 4) {
	int amt;
	uint8_t chan = clp->buf[0];
	uint8_t cmd = clp->buf[1];
	uint16_t plen = clp->buf[2] << 8 | clp->buf[3];
	//printf("chan %d cmd %d plen %d\n", chan, cmd, plen);
	if (clp->amt < plen + 4)
	    return;
	if (cmd == 0) {
	    if (chan > NUM_CHAN) {
		printf("Channel %d from client %s out of range\n", chan, clp->addrtxt);
		goto pullup;
	    }
	    if (plen > NUM_LEDS * 3) {
		printf("Packet size %d from client %s out of range\n", plen, clp->addrtxt);
		goto pullup;
	    }
	    memcpy(&ledbuf[chan][0], &clp->buf[4], plen);
	    ledbuf_dirty = 1;
	} else {
	    warnx("Unknown command 0x%02x from %s", cmd, clp->addrtxt);
	}
     pullup:
	amt = plen + 4;
	memmove(&clp->buf[0], &clp->buf[amt], clp->amt - amt);
	clp->amt -= amt;
	//printf("Pulling packet down %d, amt now %d\n", amt, clp->amt);
    }
}

static void
closesock(int fd, struct clientshead *head, int *numclients) {
    struct clentry *clp;

    clp = findsock(fd, head);
    if (clp == NULL)
	return;

    SLIST_REMOVE(head, clp, clentry, entries);
    close(clp->fd);
    (*numclients)--;
    warnx("Closed connection from %s", clp->addrtxt);

    free(clp);
}
