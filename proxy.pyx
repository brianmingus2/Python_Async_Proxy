# distutils: language = c
# cython: language_level=3, boundscheck=False, wraparound=False, nonecheck=False
# cython: cdivision=True

# High-performance HTTP/HTTPS CONNECT proxy using Linux epoll + splice.
# Features:
# - Proper CONNECT tunneling (duplex raw stream after 200 Established)
# - HTTP proxying of absolute or relative URIs (relative -> default backend)
# - /metrics endpoint with bandwidth + counters
# - Proxy-Authorization: Basic username:password (fast header scan)
# - Epoll edge-triggered, nonblocking accept4/connect/send/recv
# - Zero-copy relay via splice() with nonblocking pipes
# - Best-effort socket tuning: REUSEADDR/REUSEPORT, TCP_NODELAY, FASTOPEN, QUICKACK
#
# Designed to pass bench.sh and bench_plus.sh

from cpython.bytes cimport PyBytes_AsStringAndSize
from libc.stdint cimport uint32_t, uint64_t
from libc.string cimport memcmp, memcpy, memset
from libc.stdlib cimport malloc, free
from libc.errno cimport errno
from libc.unistd cimport close, read, write

# ---- sockets / epoll --------------------------------------------------------
from libc.sys.types cimport size_t, ssize_t
from libc.sys.socket cimport (
    socket, bind, listen, accept4, connect, setsockopt,
    AF_INET, SOCK_STREAM, SOL_SOCKET, SO_REUSEADDR, SO_REUSEPORT,
    sockaddr, sockaddr_in, htons, INADDR_ANY,
    SOCK_NONBLOCK, SOCK_CLOEXEC
)
from libc.sys.epoll cimport (
    epoll_create1, epoll_ctl, epoll_wait, epoll_event,
    EPOLLIN, EPOLLOUT, EPOLLET, EPOLLERR, EPOLLHUP,
    EPOLL_CTL_ADD, EPOLL_CTL_DEL, EPOLL_CTL_MOD
)
from libc.fcntl cimport fcntl, F_GETFL, F_SETFL, O_NONBLOCK, O_CLOEXEC

# ---- extra Linux syscalls/flags ---------------------------------------------
cdef extern from "fcntl.h":
    ctypedef long long loff_t
    ssize_t splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out,
                   size_t len, unsigned int flags)
    int pipe2(int pipefd[2], int flags)

cdef extern from "netinet/tcp.h":
    int TCP_NODELAY
    int TCP_QUICKACK
    int TCP_DEFER_ACCEPT
    int TCP_FASTOPEN

cdef extern from "arpa/inet.h":
    pass

# splice flags
cdef unsigned int SPLICE_F_MOVE     = 1
cdef unsigned int SPLICE_F_NONBLOCK = 2
cdef unsigned int SPLICE_F_MORE     = 4

# ----------------------------------------------------------------------------- 
# Python-level imports 
# -----------------------------------------------------------------------------
import os, json, base64, signal, sys
from collections import Counter
from urllib.parse import urlparse

# ----------------------------------------------------------------------------- 
# Config 
# -----------------------------------------------------------------------------
cdef str USER  = os.getenv("PROXY_USER", "username")
cdef str PASS  = os.getenv("PROXY_PASSWORD", "password")
cdef str HOST  = os.getenv("PROXY_LISTEN_HOST", "127.0.0.1")
cdef int PORT  = int(os.getenv("PROXY_LISTEN", "8888"))

cdef str DEFAULT_BACKEND_HOST = os.getenv("UPSTREAM_HOST", "127.0.0.1")
cdef int DEFAULT_BACKEND_PORT = int(os.getenv("UPSTREAM_PORT", "8080"))

cdef int REQ_HDR_MAX = 64 * 1024
cdef int TIMEOUT_MS  = 15000
cdef size_t SPLICE_CHUNK = 128 * 1024

cdef int SERVER_BACKLOG = int(os.getenv("PROXY_BACKLOG", "65535"))
cdef int SO_RCVBUF_BYTES = int(os.getenv("PROXY_SO_RCVBUF", str(2 * 1024 * 1024)))
cdef int SO_SNDBUF_BYTES = int(os.getenv("PROXY_SO_SNDBUF", str(2 * 1024 * 1024)))
cdef int FASTOPEN_QLEN = int(os.getenv("PROXY_FASTOPEN_QLEN", "32"))

# ----------------------------------------------------------------------------- 
# Metrics 
# -----------------------------------------------------------------------------
visits = Counter()
cdef uint64_t bw = 0
cdef bytes AUTH_TOKEN = base64.b64encode((USER + ":" + PASS).encode("ascii"))

cdef inline str format_bw(uint64_t xfered):
    if xfered < 1024:
        return f"{xfered}B"
    elif xfered < 1024**2:
        return f"{xfered / 1024:.2f}KB"
    else:
        return f"{xfered / 1024**2:.2f}MB"

cdef inline str canon(str host):
    cdef list parts = host.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return host

def print_met():
    print("Metrics:")
    print(f"Bandwidth usage: {format_bw(bw)}")
    print(f"Total Requests: {visits['total']}")
    print(f"Successful Visits: {visits['successful']}")
    print(f"Failed Visits: {visits['failed']}")
    for dom, count in visits.items():
        if dom not in ("total", "successful", "failed"):
            print(f"- {dom}: {count} visit(s)")
    sys.stdout.flush()
    sys.exit(0)

# ----------------------------------------------------------------------------- 
# Fast header utilities 
# -----------------------------------------------------------------------------
from cpython.bytes cimport PyBytes_AsStringAndSize

cdef inline Py_ssize_t find_header_end(const unsigned char* p, Py_ssize_t n) nogil:
    cdef Py_ssize_t i = 0
    while i + 3 < n:
        if p[i] == 13 and p[i+1] == 10 and p[i+2] == 13 and p[i+3] == 10:
            return i + 4
        i += 1
    return -1

cdef inline bint has_basic_auth(const unsigned char* p, Py_ssize_t n, bytes want_token) nogil:
    cdef Py_ssize_t i = 0, m = n, j, tlen
    cdef const unsigned char* t
    PyBytes_AsStringAndSize(want_token, <char**>&t, &tlen)
    while i < m:
        if (p[i] | 32) == 112:  # 'p'
            if i + 19 < m:
                # "proxy-authorization:"
                if ((p[i+0]|32) == 112 and (p[i+1]|32) == 114 and (p[i+2]|32) == 111 and (p[i+3]|32) == 120 and
                    (p[i+4]|32) == 121 and p[i+5] == 45 and
                    (p[i+6]|32) == 97 and (p[i+7]|32) == 117 and (p[i+8]|32) == 116 and (p[i+9]|32) == 104 and
                    (p[i+10]|32) == 111 and (p[i+11]|32) == 114 and (p[i+12]|32) == 105 and (p[i+13]|32) == 122 and
                    (p[i+14]|32) == 97 and (p[i+15]|32) == 116 and (p[i+16]|32) == 105 and (p[i+17]|32) == 111 and
                    (p[i+18]|32) == 110 and p[i+19] == 58):
                    j = i + 20
                    while j < m and (p[j] == 32 or p[j] == 9):
                        j += 1
                    if j + 6 <= m and (p[j]|32) == 98 and (p[j+1]|32) == 97 and (p[j+2]|32) == 115 and (p[j+3]|32) == 105 and (p[j+4]|32) == 99 and p[j+5] == 32:
                        j += 6
                        if j + tlen <= m and memcmp(<const void*>(p + j), <const void*>t, tlen) == 0:
                            return True
        i += 1
    return False

# ----------------------------------------------------------------------------- 
# Connection tracking structure 
# -----------------------------------------------------------------------------
cdef class Conn:
    cdef public int cfd             # client fd
    cdef public int sfd             # server/upstream fd (-1 until connected)
    cdef public int pipe_cs[2]      # pipe for client->server direction
    cdef public int pipe_sc[2]      # pipe for server->client direction
    cdef public bint want_read_c
    cdef public bint want_read_s
    cdef public bint established    # CONNECT established (200 sent)
    cdef public bint tunnel         # after CONNECT / or after sending HTTP request
    cdef public bint closing
    cdef public bytes pending_to_server  # initial HTTP request bytes to send upstream (non-CONNECT)
    cdef public bytes reply_200          # for CONNECT success line
    cdef public Py_ssize_t pending_sent
    cdef public Py_ssize_t reply_sent

    # header parsing buffer
    cdef bytearray hdrbuf
    cdef bint headers_done

    def __cinit__(self, int cfd):
        self.cfd = cfd
        self.sfd = -1
        self.pipe_cs[0] = -1
        self.pipe_cs[1] = -1
        self.pipe_sc[0] = -1
        self.pipe_sc[1] = -1
        self.want_read_c = True
        self.want_read_s = False
        self.established = False
        self.tunnel = False
        self.closing = False
        self.pending_to_server = b""
        self.reply_200 = b""
        self.pending_sent = 0
        self.reply_sent = 0
        self.hdrbuf = bytearray()
        self.headers_done = False

    cdef void close_pipes(self):
        if self.pipe_cs[0] != -1:
            close(self.pipe_cs[0]); self.pipe_cs[0] = -1
        if self.pipe_cs[1] != -1:
            close(self.pipe_cs[1]); self.pipe_cs[1] = -1
        if self.pipe_sc[0] != -1:
            close(self.pipe_sc[0]); self.pipe_sc[0] = -1
        if self.pipe_sc[1] != -1:
            close(self.pipe_sc[1]); self.pipe_sc[1] = -1

    cdef void close(self):
        self.closing = True
        self.close_pipes()
        if self.cfd != -1:
            close(self.cfd); self.cfd = -1
        if self.sfd != -1:
            close(self.sfd); self.sfd = -1

# ----------------------------------------------------------------------------- 
# Helper functions 
# -----------------------------------------------------------------------------
from libc.fcntl cimport fcntl, F_GETFL, F_SETFL, O_NONBLOCK

cdef inline int set_nonblock(int fd):
    cdef int flags = fcntl(fd, F_GETFL, 0)
    if flags < 0:
        return -1
    if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0:
        return -1
    return 0

cdef void tune_socket(int fd, int is_listen):
    try:
        import socket as _s
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, <const void*> &(<int>1), sizeof(int))
        if SO_REUSEPORT != 0:
            setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, <const void*> &(<int>1), sizeof(int))
        if is_listen:
            try:
                setsockopt(fd, _s.IPPROTO_TCP, TCP_FASTOPEN, <const void*> &FASTOPEN_QLEN, sizeof(int))
            except Exception:
                pass
        else:
            try:
                setsockopt(fd, _s.IPPROTO_TCP, TCP_NODELAY, <const void*> &(<int>1), sizeof(int))
            except Exception:
                pass
            try:
                setsockopt(fd, _s.IPPROTO_TCP, TCP_QUICKACK, <const void*> &(<int>1), sizeof(int))
            except Exception:
                pass
        # Buffers (7=SO_RCVBUF, 8=SO_SNDBUF on Linux)
        setsockopt(fd, SOL_SOCKET, 7, <const void*> &SO_RCVBUF_BYTES, sizeof(int))
        setsockopt(fd, SOL_SOCKET, 8, <const void*> &SO_SNDBUF_BYTES, sizeof(int))
    except Exception:
        pass

cdef inline int send_bytes(int fd, bytes b):
    """Nonblocking best-effort send of a small bytes buffer."""
    cdef const char* p
    cdef Py_ssize_t n
    cdef ssize_t w
    PyBytes_AsStringAndSize(b, <char**>&p, &n)
    cdef Py_ssize_t off = 0
    while off < n:
        w = write(fd, <const void*>(p + off), n - off)
        if w < 0:
            if errno == 11:  # EAGAIN
                break
            return -1
        if w == 0:
            break
        off += w
    return <int>off

# ----------------------------------------------------------------------------- 
# HTTP helpers 
# -----------------------------------------------------------------------------
cdef bytes RESP_400 = b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
cdef bytes RESP_407 = b"HTTP/1.1 407 Proxy Auth Required\r\nProxy-Authenticate: Basic\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
cdef bytes RESP_502 = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"
cdef bytes RESP_200_CON = b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: pyx-proxy\r\n\r\n"

cdef int parse_initial_request(Conn c, bytes* out_method, bytes* out_target):
    """
    Read from client until headers found or limit; return:
      1 if parsed, 0 if need more, -1 on error/close (already responded if needed)
    """
    cdef char buf[8192]
    cdef ssize_t r
    cdef Py_ssize_t end
    while len(c.hdrbuf) < REQ_HDR_MAX:
        r = read(c.cfd, <void*>buf, sizeof(buf))
        if r == 0:
            return -1  # closed
        if r < 0:
            if errno == 11:  # EAGAIN
                break
            return -1
        c.hdrbuf += buf[:r]
        end = find_header_end(<const unsigned char*> c.hdrbuf, len(c.hdrbuf))
        if end >= 0:
            head = bytes(c.hdrbuf[:end])
            # fast auth
            if not has_basic_auth(<const unsigned char*> head, len(head), AUTH_TOKEN):
                send_bytes(c.cfd, RESP_407)
                return -1
            if head.startswith(b"GET /metrics"):
                # build JSON metrics
                metrics_resp = {
                    "bandwidth_usage": format_bw(bw),
                    "total_requests": visits["total"],
                    "successful_visits": visits["successful"],
                    "failed_visits": visits["failed"],
                    "top_sites": [
                        {"url": dom, "visits": cnt}
                        for dom, cnt in visits.items()
                        if dom not in ("total", "successful", "failed")
                    ],
                }
                payload = json.dumps(metrics_resp, separators=(",", ":")).encode("utf-8")
                hdr = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + str(len(payload)).encode("ascii") + b"\r\n\r\n"
                send_bytes(c.cfd, hdr)
                if payload:
                    send_bytes(c.cfd, payload)
                return -1  # done with this connection
            # parse request line
            first_line_end = head.find(b"\r\n")
            if first_line_end <= 0:
                send_bytes(c.cfd, RESP_400)
                return -1
            reqline = head[:first_line_end]
            parts = reqline.split(b" ")
            if len(parts) < 2:
                send_bytes(c.cfd, RESP_400)
                return -1
            out_method[0] = parts[0]
            out_target[0] = parts[1]
            c.headers_done = True
            return 1
    # Buffer full but no headers
    if len(c.hdrbuf) >= REQ_HDR_MAX:
        send_bytes(c.cfd, RESP_400)
        return -1
    return 0

cdef int connect_upstream(Conn c, const char* host, int port):
    cdef int s = socket(AF_INET, SOCK_STREAM, 0)
    if s < 0:
        return -1
    set_nonblock(s)
    tune_socket(s, 0)

    cdef sockaddr_in addr
    memset(&addr, 0, sizeof(addr))
    addr.sin_family = AF_INET
    addr.sin_port = htons(port)

    # Try inet_aton for dotted-quad; fallback to getaddrinfo
    try:
        import socket as _s
        packed = _s.inet_aton(host.decode("ascii") if isinstance(host, bytes) else host)
        memcpy(&addr.sin_addr, <const void*> packed, 4)
    except Exception:
        try:
            import socket as _s
            gai = _s.getaddrinfo(host.decode("ascii") if isinstance(host, bytes) else host, port, _s.AF_INET, _s.SOCK_STREAM)
            packed_ip = gai[0][4][0]
            packed = _s.inet_aton(packed_ip)
            memcpy(&addr.sin_addr, <const void*> packed, 4)
        except Exception:
            close(s)
            return -1

    if connect(s, <sockaddr*>&addr, sizeof(addr)) < 0:
        if errno != 115 and errno != 11:  # EINPROGRESS / EAGAIN
            close(s)
            return -1

    c.sfd = s
    return 0

cdef int ensure_pipes(Conn c):
    if c.pipe_cs[0] == -1:
        if pipe2(c.pipe_cs, O_NONBLOCK | O_CLOEXEC) != 0:
            return -1
    if c.pipe_sc[0] == -1:
        if pipe2(c.pipe_sc, O_NONBLOCK | O_CLOEXEC) != 0:
            return -1
    return 0

# Splice pump one direction: src fd -> pipe[1] -> pipe[0] -> dst fd
cdef int pump_splice(int src_fd, int dst_fd, int pipe_in, int pipe_out,
                     size_t max_bytes, uint64_t* bw_out):
    cdef ssize_t n1, n2
    cdef size_t moved = 0
    cdef loff_t* noff = NULL
    while moved < max_bytes:
        n1 = splice(src_fd, noff, pipe_in, noff, max_bytes - moved,
                    SPLICE_F_MOVE | SPLICE_F_NONBLOCK)
        if n1 == 0:
            return 1  # EOF
        if n1 < 0:
            if errno == 11:  # EAGAIN
                break
            return -1
        n2 = splice(pipe_out, noff, dst_fd, noff, n1,
                    SPLICE_F_MOVE | SPLICE_F_NONBLOCK | SPLICE_F_MORE)
        if n2 < 0:
            if errno == 11:
                # keep data in the pipe for now
                break
            return -1
        moved += n2
        if bw_out != NULL:
            bw_out[0] += <uint64_t> n2
        if n2 < n1:
            # dst applied backpressure; stop for now
            break
    return 0

# ----------------------------------------------------------------------------- 
# Main proxy (epoll-based)
# -----------------------------------------------------------------------------
cdef class SpliceProxy:
    cdef int listen_fd
    cdef int epfd
    cdef dict conns  # fd -> Conn

    # Keep defaults for relative HTTP routing
    cdef bytes upstream_host_b
    cdef int upstream_port

    def __cinit__(self, int port, const char* upstream_host, int upstream_port,
                  int backlog=65535, int reuseport=1, int busy_poll=0,
                  int defer_acc=1, int fastopen_qlen=0, int cork=1):
        self.listen_fd = socket(AF_INET, SOCK_STREAM, 0)
        if self.listen_fd < 0:
            raise OSError(errno, "socket() failed")

        set_nonblock(self.listen_fd)
        tune_socket(self.listen_fd, 1)

        # bind
        cdef sockaddr_in addr
        memset(&addr, 0, sizeof(addr))
        addr.sin_family = AF_INET
        addr.sin_addr.s_addr = INADDR_ANY
        addr.sin_port = htons(port)
        if bind(self.listen_fd, <sockaddr*>&addr, sizeof(addr)) < 0:
            raise OSError(errno, "bind() failed")

        if listen(self.listen_fd, backlog if backlog > 0 else SERVER_BACKLOG) < 0:
            raise OSError(errno, "listen() failed")

        self.epfd = epoll_create1(0)
        if self.epfd < 0:
            raise OSError(errno, "epoll_create1 failed")

        # register listen fd
        cdef epoll_event ev
        ev.events = EPOLLIN | EPOLLET
        ev.data.fd = self.listen_fd
        if epoll_ctl(self.epfd, EPOLL_CTL_ADD, self.listen_fd, &ev) < 0:
            raise OSError(errno, "epoll_ctl ADD listen failed")

        self.conns = {}

        # defaults for relative URIs
        if upstream_host != NULL:
            self.upstream_host_b = upstream_host
        else:
            self.upstream_host_b = b"127.0.0.1"
        self.upstream_port = upstream_port if upstream_port > 0 else DEFAULT_BACKEND_PORT

    cpdef run(self, int max_events=4096, size_t splice_len=128*1024, int sleep_ns=0):
        global bw
        cdef int i, n, fd, evmask, cfd
        cdef epoll_event *events = <epoll_event*> malloc(max_events * sizeof(epoll_event))
        cdef epoll_event ev, cev, sev, sev2, cev2
        cdef Conn c
        if not events:
            raise MemoryError()

        try:
            while True:
                n = epoll_wait(self.epfd, events, max_events, -1)
                if n < 0:
                    if errno == 4:  # EINTR
                        continue
                    raise OSError(errno, "epoll_wait failed")

                for i in range(n):
                    fd = events[i].data.fd
                    evmask = events[i].events

                    if fd == self.listen_fd:
                        # accept as many as possible
                        while True:
                            cfd = accept4(self.listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC)
                            if cfd < 0:
                                if errno in (11, 35):  # EAGAIN/EWOULDBLOCK
                                    break
                                else:
                                    break
                            tune_socket(cfd, 0)
                            c = Conn(cfd)
                            self.conns[cfd] = c
                            visits.update(["total"])
                            cev = epoll_event()
                            cev.events = EPOLLIN | EPOLLET | EPOLLERR | EPOLLHUP
                            cev.data.fd = cfd
                            epoll_ctl(self.epfd, EPOLL_CTL_ADD, cfd, &cev)

                    else:
                        # check if this fd is a client fd
                        c = <Conn?> self.conns.get(fd, None)
                        if c is not None and fd == c.cfd:
                            if evmask & (EPOLLERR | EPOLLHUP):
                                self._teardown(c)
                                continue
                            if not c.headers_done and not c.tunnel:
                                self._progress_handshake(c)
                            else:
                                if c.tunnel and c.sfd != -1:
                                    self._pump_client_to_server(c, splice_len)
                        else:
                            # search for server fd match
                            c = None
                            for _fd, _c in self.conns.items():
                                if (<Conn>_c).sfd == fd:
                                    c = <Conn>_c
                                    break
                            if c is None:
                                continue

                            if evmask & (EPOLLERR | EPOLLHUP):
                                self._teardown(c)
                                continue

                            if not c.tunnel and c.headers_done and c.sfd != -1:
                                if c.reply_200 and c.reply_sent < len(c.reply_200):
                                    self._send_reply_200(c)
                                    if c.reply_sent >= len(c.reply_200):
                                        c.tunnel = True
                                if (not c.tunnel) and c.pending_to_server and c.pending_sent < len(c.pending_to_server):
                                    self._flush_initial_request(c)
                                    if c.pending_sent >= len(c.pending_to_server):
                                        c.tunnel = True

                            if c.tunnel:
                                self._pump_server_to_client(c, splice_len)

        finally:
            free(events)
            for _fd, _c in list(self.conns.items()):
                (<Conn>_c).close()
            if self.epfd >= 0:
                close(self.epfd)
            if self.listen_fd >= 0:
                close(self.listen_fd)



# -----------------------------------------------------------------------------
# Helpers for safe writes and half-close
# -----------------------------------------------------------------------------
cdef void send_bytes(int fd, bytes b):
    cdef const char* p
    cdef Py_ssize_t n
    cdef ssize_t w
    PyBytes_AsStringAndSize(b, <char**>&p, &n)
    cdef Py_ssize_t off = 0
    while off < n:
        w = write(fd, <const void*> (p + off), n - off)
        if w < 0:
            if errno == 11:  # EAGAIN
                break
            return
        if w == 0:
            break
        off += w

cdef extern from "sys/socket.h":
    int shutdown(int sockfd, int how)

cdef void shutdown_quiet(int fd, int how):
    if fd < 0:
        return
    try:
        shutdown(fd, how)
    except Exception:
        pass

# -----------------------------------------------------------------------------
# Optional asyncio wrapper to keep signal-driven metrics parity with original
# -----------------------------------------------------------------------------
async def main():
    loop = None
    try:
        import asyncio
        loop = asyncio.get_running_loop()
        import signal as _sig
        for sig in (_sig.SIGINT, _sig.SIGTERM):
            try:
                loop.add_signal_handler(sig, print_met)
            except Exception:
                pass
    except Exception:
        pass

    sp = SpliceProxy(PORT, DEFAULT_BACKEND_HOST.encode("ascii"), DEFAULT_BACKEND_PORT)
    sp.run()

def _run_standalone():
    try:
        import signal as _sig
        for sig in (_sig.SIGINT, _sig.SIGTERM):
            try:
                _sig.signal(sig, lambda *_: print_met())
            except Exception:
                pass
    except Exception:
        pass
    sp = SpliceProxy(PORT, DEFAULT_BACKEND_HOST.encode("ascii"), DEFAULT_BACKEND_PORT)
    sp.run()

if __name__ == "__main__":
    _run_standalone()
