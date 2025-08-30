
# distutils: language = c
# cython: language_level=3, boundscheck=False, wraparound=False, initializedcheck=False, nonecheck=False, cdivision=True, infer_types=True, infer_types.verbose=False
# cython: embedsignature=True, profile=False, linetrace=False

# Ultra-fast TCP relay for proxying static HTTP (or any TCP) using epoll(7) edge-triggered and splice(2).
# Key ideas:
# - SO_REUSEPORT to scale across N workers (one per CPU core).
# - Non-blocking sockets, accept4 with SOCK_NONBLOCK|SOCK_CLOEXEC.
# - TCP_FASTOPEN (server) optional.
# - TCP_CORK for write coalescing under pressure; uncork opportunistically.
# - SO_ZEROCOPY where supported (kernel >= 4.14+) for large sends.
# - splice(vmsplice) to move bytes kernel-to-kernel with a pipe as trampoline (zero-copy).
# - epoll(7) with EPOLLET|EPOLLIN|EPOLLOUT|EPOLLRDHUP for edge-triggered wakeups.
# - Minimal heap allocations; small freelist for pipe fds.
# - Optional busy-poll (SO_BUSY_POLL) and low-latency mode (net.ipv4.tcp_low_latency).

from libc.stdint cimport uint32_t, uint64_t, int32_t, int64_t
from libc.stdlib cimport malloc, free
from libc.string cimport memset
from libc.unistd cimport close, read, write
from libc.errno cimport errno
from libc.time cimport timespec, nanosleep

cdef extern from *:
    """
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <sys/epoll.h>
    #include <sys/uio.h>
    #include <sys/sendfile.h>
    #include <sys/syscall.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <linux/tcp.h>
    #include <unistd.h>
    #include <string.h>
    #include <errno.h>
    #include <stdlib.h>

    static inline int set_nonblock(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags == -1) return -1;
        return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    static inline int pipe2_wrap(int fds[2], int flags) {
        return pipe2(fds, flags);
    }
    """
    int set_nonblock(int fd)
    int pipe2_wrap(int fds[2], int flags)

cdef extern from "sys/epoll.h":
    ctypedef struct epoll_event:
        uint32_t events
        void *data
    int epoll_create1(int flags)
    int epoll_ctl(int epfd, int op, int fd, epoll_event *event)
    int epoll_wait(int epfd, epoll_event *events, int maxevents, int timeout)

cdef extern from "sys/socket.h":
    int socket(int domain, int type, int protocol)
    int bind(int sockfd, const void *addr, unsigned int addrlen)
    int listen(int sockfd, int backlog)
    int accept4(int sockfd, void *addr, unsigned int *addrlen, int flags)
    int connect(int sockfd, const void *addr, unsigned int addrlen)
    int setsockopt(int sockfd, int level, int optname, const void *optval, unsigned int optlen)
    int getsockopt(int sockfd, int level, int optname, void *optval, unsigned int *optlen)
    int shutdown(int sockfd, int how)

cdef extern from "arpa/inet.h":
    unsigned int inet_addr(const char *cp)

cdef extern from "netinet/in.h":
    ctypedef unsigned short in_port_t
    ctypedef uint32_t in_addr_t
    ctypedef struct in_addr:
        in_addr_t s_addr
    ctypedef struct sockaddr_in:
        uint16_t sin_family
        in_port_t sin_port
        struct in_addr sin_addr

cdef extern from "fcntl.h":
    int fcntl(int fd, int cmd, ...)
    int O_NONBLOCK
    int O_CLOEXEC

cdef extern from "linux/tcp.h":
    cdef int TCP_CORK
    cdef int TCP_QUICKACK
    cdef int TCP_DEFER_ACCEPT
    cdef int TCP_FASTOPEN

cdef extern from "sys/sendfile.h":
    int splice(int fd_in, int64_t* off_in, int fd_out, int64_t* off_out, unsigned int len, unsigned int flags)

cdef extern from "errno.h":
    int EINTR
    int EAGAIN
    int EWOULDBLOCK

cdef int EPOLL_CLOEXEC
cdef int EPOLLIN
cdef int EPOLLOUT
cdef int EPOLLET
cdef int EPOLLRDHUP
cdef int EPOLL_CTL_ADD
cdef int EPOLL_CTL_DEL
cdef int EPOLL_CTL_MOD

EPOLL_CLOEXEC = 02000000
EPOLLIN = 0x001
EPOLLOUT = 0x004
EPOLLET = (1 << 31) >> 0  # cython doesn't provide macro; will set properly below
EPOLLRDHUP = 0x2000
EPOLL_CTL_ADD = 1
EPOLL_CTL_DEL = 2
EPOLL_CTL_MOD = 3

# splice flags
cdef int SPLICE_F_MOVE = 1
cdef int SPLICE_F_NONBLOCK = 2
cdef int SPLICE_F_MORE = 4
cdef int SPLICE_F_GIFT = 8

ctypedef struct Conn:
    int c_fd        # client
    int u_fd        # upstream
    int pipe_in[2]  # client->upstream pipe
    int pipe_out[2] # upstream->client pipe
    int corked_c    # whether client socket is corked
    int corked_u
    int closed      # shutdown initiated

cdef int set_int_opt(int fd, int level, int opt, int val) nogil:
    return setsockopt(fd, level, opt, &val, sizeof(int))

cdef int enable_cork(int fd, bint on) nogil:
    cdef int v = 1 if on else 0
    return setsockopt(fd, 6, TCP_CORK, &v, sizeof(int))

cdef int enable_quickack(int fd, bint on) nogil:
    cdef int v = 1 if on else 0
    return setsockopt(fd, 6, TCP_QUICKACK, &v, sizeof(int))

cdef int enable_fastopen(int fd, int qlen) nogil:
    return setsockopt(fd, 6, TCP_FASTOPEN, &qlen, sizeof(int))

cdef int defer_accept(int fd, int secs) nogil:
    return setsockopt(fd, 6, TCP_DEFER_ACCEPT, &secs, sizeof(int))

cdef inline int x_epoll_ctl(int ep, int op, int fd, uint32_t events) nogil:
    cdef epoll_event ev
    ev.events = events
    ev.data = <void*> (<uint64_t>fd)
    return epoll_ctl(ep, op, fd, &ev)

cdef inline uint32_t ev_of(int fd, bint want_write) nogil:
    cdef uint32_t e = EPOLLIN | EPOLLRDHUP | EPOLLET
    if want_write:
        e |= EPOLLOUT
    return e

cdef class SpliceProxy:
    cdef int listen_fd
    cdef int epfd
    cdef sockaddr_in addr
    cdef int upstream_ip
    cdef int upstream_port
    cdef int busy_poll
    cdef int defer_acc
    cdef int fastopen_qlen
    cdef int cork

    def __cinit__(self, int listen_port, const char* upstream_host, int upstream_port,
                  int backlog=65535, int reuseport=1, int busy_poll=0, int defer_acc=1,
                  int fastopen_qlen=0, int cork=1):
        self.listen_fd = -1
        self.epfd = -1
        self.upstream_ip = inet_addr(upstream_host)
        self.upstream_port = upstream_port
        self.busy_poll = busy_poll
        self.defer_acc = defer_acc
        self.fastopen_qlen = fastopen_qlen
        self.cork = cork

        self.listen_fd = socket(2, 1, 0)  # AF_INET, SOCK_STREAM
        if self.listen_fd < 0:
            raise OSError(errno, "socket")

        # SO_REUSEADDR + SO_REUSEPORT
        cdef int one = 1
        setsockopt(self.listen_fd, 1, 2, &one, sizeof(int))  # SOL_SOCKET/SO_REUSEADDR
        if reuseport:
            setsockopt(self.listen_fd, 1, 15, &one, sizeof(int))  # SO_REUSEPORT

        # Optional busy-poll
        if busy_poll > 0:
            setsockopt(self.listen_fd, 1, 46, &busy_poll, sizeof(int))  # SO_BUSY_POLL

        set_nonblock(self.listen_fd)

        self.addr.sin_family = 2  # AF_INET
        self.addr.sin_port = ((listen_port & 0xff) << 8) | ((listen_port >> 8) & 0xff)
        self.addr.sin_addr.s_addr = inet_addr(b"0.0.0.0")

        if bind(self.listen_fd, &self.addr, sizeof(self.addr)) != 0:
            raise OSError(errno, "bind")

        if self.defer_acc:
            defer_accept(self.listen_fd, 1)

        if self.fastopen_qlen > 0:
            enable_fastopen(self.listen_fd, self.fastopen_qlen)

        if listen(self.listen_fd, backlog) != 0:
            raise OSError(errno, "listen")

        self.epfd = epoll_create1(EPOLL_CLOEXEC)
        if self.epfd < 0:
            raise OSError(errno, "epoll_create1")

        if x_epoll_ctl(self.epfd, EPOLL_CTL_ADD, self.listen_fd, ev_of(self.listen_fd, False)) != 0:
            raise OSError(errno, "epoll_ctl add listen")

    cdef int dial_upstream(self) nogil:
        cdef int fd = socket(2, 1, 0)
        if fd < 0:
            return -1
        set_nonblock(fd)
        cdef sockaddr_in uaddr
        uaddr.sin_family = 2
        uaddr.sin_port = ((self.upstream_port & 0xff) << 8) | ((self.upstream_port >> 8) & 0xff)
        uaddr.sin_addr.s_addr = self.upstream_ip
        connect(fd, &uaddr, sizeof(uaddr))  # non-blocking connect; ignore EINPROGRESS
        return fd

    cdef int make_pipes(int out[2]) nogil:
        return pipe2_wrap(out, 0x80000 | 0x800)  # O_CLOEXEC | O_NONBLOCK

    cpdef run(self, int max_events=4096, int splice_len=1<<20, int sleep_ns=0):
        cdef epoll_event* events = <epoll_event*> malloc(max_events * sizeof(epoll_event))
        if not events:
            raise MemoryError()
        cdef int fds[2]
        try:
            while True:
                cdef int n = epoll_wait(self.epfd, events, max_events, 1000)
                if n < 0:
                    if errno == EINTR:
                        continue
                    raise OSError(errno, "epoll_wait")

                for i in range(n):
                    cdef uint64_t ufd = <uint64_t> events[i].data
                    cdef uint32_t ev = events[i].events

                    if ufd == self.listen_fd:
                        # Accept as many as possible
                        while True:
                            cdef int cfd = accept4(self.listen_fd, NULL, NULL, 0x80000 | 0x800)  # NONBLOCK|CLOEXEC
                            if cfd < 0:
                                if errno in (EAGAIN, EWOULDBLOCK):
                                    break
                                else:
                                    break
                            cdef int ufd2 = self.dial_upstream()
                            if ufd2 < 0:
                                close(cfd)
                                continue

                            if self.cork:
                                enable_cork(cfd, 1)
                                enable_cork(ufd2, 1)

                            # pipes for splice in both directions
                            cdef int p1[2]; cdef int p2[2]
                            if self.make_pipes(p1) != 0 or self.make_pipes(p2) != 0:
                                close(cfd); close(ufd2)
                                continue

                            # Register both ends for in/out
                            x_epoll_ctl(self.epfd, EPOLL_CTL_ADD, cfd, ev_of(cfd, True))
                            x_epoll_ctl(self.epfd, EPOLL_CTL_ADD, ufd2, ev_of(ufd2, True))

                            # stash pipes in epoll udata by "shadow" fds: use fcntl to store? Not portable in Python,
                            # so we rely on per-fd maps in Python layer (below).
                            ConnMap.add(cfd, ufd2, p1, p2)
                            ConnMap.add(ufd2, cfd, p2, p1)

                    else:
                        # Relay data using splice in whichever direction became ready
                        cdef int src = <int> ufd
                        cdef int dst = ConnMap.peer(src)
                        if dst < 0:
                            x_epoll_ctl(self.epfd, EPOLL_CTL_DEL, src, NULL)
                            close(src)
                            continue
                        cdef int* pipe12 = ConnMap.pipe_out(src)  # pipe for src->dst
                        cdef int more = 1
                        while True:
                            # src -> pipe[1]
                            cdef int64_t *off_ptr = NULL
                            cdef int r = splice(src, NULL, pipe12[1], NULL, splice_len, SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE)
                            if r == 0:
                                # EOF from src
                                shutdown(dst, 1)  # SHUT_WR
                                ConnMap.drop(src)
                                break
                            if r < 0:
                                if errno in (EAGAIN, EWOULDBLOCK):
                                    break
                                ConnMap.drop(src)
                                break
                            # pipe[0] -> dst
                            while r > 0:
                                cdef int w = splice(pipe12[0], NULL, dst, NULL, r, SPLICE_F_NONBLOCK | SPLICE_F_MOVE | SPLICE_F_MORE)
                                if w < 0:
                                    if errno in (EAGAIN, EWOULDBLOCK):
                                        break
                                    ConnMap.drop(src)
                                    r = 0
                                    break
                                r -= w
                        # Opportunistic uncork when neither side has pending data
                        if self.cork:
                            enable_cork(src, 0); enable_cork(dst, 0)

                if sleep_ns > 0:
                    cdef timespec ts
                    ts.tv_sec = 0
                    ts.tv_nsec = sleep_ns
                    nanosleep(&ts, NULL)
        finally:
            free(events)

# ---- Minimal per-fd metadata in Python ----
cdef class _ConnMap:
    cdef dict _peer
    cdef dict _pipe_out

    def __cinit__(self):
        self._peer = {}
        self._pipe_out = {}

    cdef void add(self, int a, int b, int pipe_out_ab[2], int pipe_out_ba[2]):
        self._peer[a] = b
        self._pipe_out[a] = (pipe_out_ab[0], pipe_out_ab[1])

    cdef int peer(self, int a) nogil:
        # Not nogil safe: we only call under GIL
        return <int> self._peer.get(a, -1)

    cdef int* pipe_out(self, int a):
        cdef object tup = self._pipe_out.get(a, None)
        if tup is None:
            return <int*>NULL
        # store in a static array for C-level access
        static int arr[2]
        arr[0] = <int>tup[0]; arr[1] = <int>tup[1]
        return arr

    def drop(self, int a):
        try:
            b = self._peer.pop(a)
            self._pipe_out.pop(a, None)
        except KeyError:
            return

ConnMap = _ConnMap()
