# cython: language_level=3, boundscheck=False, wraparound=False, initializedcheck=False, cdivision=True
from libc.string cimport memcmp
from libc.stdint cimport uint8_t
from libc.stdlib cimport atoi
from cpython.bytes cimport PyBytes_AS_STRING, PyBytes_GET_SIZE

import asyncio
import base64
import json
import os
import signal
import sys
import time
import socket
from collections import Counter, defaultdict
from typing import Optional

# ---------- Config (matches bench.sh) ----------
cdef str USER = "username"
cdef str PASS = "password"
cdef str HOST = "127.0.0.1"
cdef int PORT = 8888
cdef int TIMEOUT = 10
cdef int BACKLOG = 8192
cdef int MAX_HEADER = 65536
cdef int READ_CHUNK = 65536
cdef bint USE_UVLOOP = True

# File to serve for "/" and "/index.html"
cdef str INDEX_PATH = "/mnt/data/index.html"

# ---------- Precomputed auth header ----------
_AUTH_PREFIX = b"proxy-authorization:"
_AUTH_VALUE = b"Basic " + base64.b64encode((USER + ":" + PASS).encode("utf-8"))
# We compare case-insensitively on header name, but value is case-sensitive per Base64
# Build a canonical lower-cased header line prefix for fast scan.
_AUTH_CANON = b"proxy-authorization: " + _AUTH_VALUE

# ---------- Metrics ----------
visits = Counter()
domain_hits = Counter()
cdef unsigned long long bw_up = 0      # bytes from client -> remote
cdef unsigned long long bw_down = 0    # bytes from remote -> client
cdef unsigned long long total_conn = 0
cdef unsigned long long active_conn = 0

# ---------- Small helpers ----------
cdef inline bint startswith_bytes(bytes data, bytes prefix):
    cdef Py_ssize_t n = PyBytes_GET_SIZE(prefix)
    cdef Py_ssize_t m = PyBytes_GET_SIZE(data)
    if m < n:
        return False
    return memcmp(PyBytes_AS_STRING(data), PyBytes_AS_STRING(prefix), n) == 0

cdef inline bytes tolower(bytes b):
    # fast ASCII-only lower
    cdef int i, n = PyBytes_GET_SIZE(b)
    cdef unsigned char* p = <unsigned char*>PyBytes_AS_STRING(b)
    cdef bytearray out = bytearray(n)
    cdef unsigned char* q = <unsigned char*>out
    cdef unsigned char ch
    for i in range(n):
        ch = p[i]
        if 65 <= ch <= 90:   # 'A'-'Z'
            q[i] = ch + 32
        else:
            q[i] = ch
    return bytes(out)

cdef inline str fmt_bytes(unsigned long long v):
    if v < 1024: return f"{v} B"
    if v < 1024**2: return f"{v/1024:.2f} KiB"
    if v < 1024**3: return f"{v/1024**2:.2f} MiB"
    return f"{v/1024**3:.2f} GiB"

cdef tuple parse_request_line(bytes head):
    # returns (method, target, version)
    # Head begins with "METHOD SP TARGET SP VERSION\r\n"
    cdef int sp1 = head.find(b' ')
    if sp1 <= 0: raise ValueError("bad request line")
    cdef int sp2 = head.find(b' ', sp1 + 1)
    if sp2 <= 0: raise ValueError("bad request line")
    cdef int cr = head.find(b'\r\n', sp2 + 1)
    if cr <= 0: raise ValueError("bad request line")
    return head[:sp1], head[sp1+1:sp2], head[sp2+1:cr]

cdef tuple split_host_port(bytes hostport, int default_port):
    cdef int colon = hostport.rfind(b':')
    if colon == -1:
        return hostport.decode('ascii', 'ignore'), default_port
    else:
        return hostport[:colon].decode('ascii', 'ignore'), atoi(hostport[colon+1:])

cdef tuple parse_absolute_uri(bytes target):
    # expects "http://host[:port]/path..."
    if not target.startswith(b"http://"):
        raise ValueError("non-http absolute URI")
    cdef int i = 7  # len("http://")
    cdef int slash = target.find(b'/', i)
    cdef bytes authority
    cdef bytes path
    if slash == -1:
        authority = target[i:]
        path = b'/'
    else:
        authority = target[i:slash]
        path = target[slash:]
    return authority, path

cdef dict parse_headers(bytes header_block):
    # returns dict(lower-case-name -> list-of-values)
    cdef dict h = defaultdict(list)
    cdef list lines = header_block.split(b"\r\n")
    cdef bytes line
    cdef int colon
    for line in lines:
        if not line:  # skip empty
            continue
        colon = line.find(b':')
        if colon <= 0:
            continue
        name = tolower(line[:colon].strip())
        value = line[colon+1:].lstrip()
        h[name].append(value)
    return h

cdef inline bint has_valid_proxy_auth(dict headers):
    cdef list vals = headers.get(b"proxy-authorization", [])
    if not vals:
        return False
    # Accept if any value equals expected value (case-sensitive for value)
    for v in vals:
        if v == _AUTH_VALUE:
            return True
    return False

async def write_simple_response(writer, int status, bytes content_type, bytes body):
    writer.write(b"HTTP/1.1 " + str(status).encode() + b" OK\r\n"
                 b"Connection: close\r\n"
                 b"Content-Type: " + content_type + b"\r\n"
                 b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    await writer.drain()

async def pipe_stream(src, dst, bint count_up):
    global bw_up, bw_down
    try:
        while True:
            data = await asyncio.wait_for(src.read(READ_CHUNK), timeout=TIMEOUT)
            if not data:
                break
            dst.write(data)
            if count_up:
                bw_up += len(data)
            else:
                bw_down += len(data)
            await dst.drain()
    except asyncio.TimeoutError:
        pass
    except (ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            await dst.drain()
        except Exception:
            pass
        try:
            dst.write_eof()
        except Exception:
            pass

async def handle_client(reader, writer):
    global total_conn, active_conn
    peer = writer.get_extra_info("peername")
    total_conn += 1
    active_conn += 1
    visits.update(["total"])

    # small socket opts
    try:
        sock = writer.get_extra_info("socket")
        if sock is not None:
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except Exception:
        pass

    try:
        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=TIMEOUT)
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return

    # Fast-path local endpoints (/metrics, /, /index.html)
    if head.startswith(b"GET /metrics"):
        # No auth required for metrics (matches bench.sh usage)
        top = sorted(domain_hits.items(), key=lambda kv: kv[1], reverse=True)[:20]
        body = json.dumps({
            "bandwidth_up": fmt_bytes(bw_up),
            "bandwidth_down": fmt_bytes(bw_down),
            "total_connections": total_conn,
            "active_connections": active_conn,
            "total_requests": visits["total"],
            "top_domains": top
        }).encode("utf-8")
        await write_simple_response(writer, 200, b"application/json", body)
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return

    if head.startswith(b"GET / ") or head.startswith(b"GET /index.html "):
        try:
            with open(INDEX_PATH, "rb") as f:
                body = f.read()
        except Exception:
            body = b""
        await write_simple_response(writer, 200, b"text/html; charset=utf-8", body)
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return

    # Parse request line & headers
    try:
        method, target, version = parse_request_line(head)
        parts = head.split(b"\r\n", 1)
        header_block = parts[1]
        if header_block.endswith(b"\r\n"):
            header_block = header_block[:-2]
        headers = parse_headers(header_block)
    except Exception:
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return


    # Auth
    if not has_valid_proxy_auth(headers):
        await write_simple_response(writer, 407, b"text/plain; charset=utf-8",
                                    b"Proxy Authentication Required")
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return

    # CONNECT (HTTPS)
    if method == b"CONNECT":
        host_s, port = split_host_port(target, 443)
        domain_hits.update([host_s])
        try:
            remote_r, remote_w = await asyncio.wait_for(
                asyncio.open_connection(host_s, port), timeout=TIMEOUT
            )
        except Exception:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            await writer.wait_closed()
            active_conn -= 1
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        t1 = asyncio.create_task(pipe_stream(reader, remote_w, True))
        t2 = asyncio.create_task(pipe_stream(remote_r, writer, False))
        try:
            await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for t in (t1, t2):
                if not t.done():
                    t.cancel()
            try:
                remote_w.close()
                await remote_w.wait_closed()
            except Exception:
                pass
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            active_conn -= 1
            return

    # Absolute-URI HTTP request (e.g., GET http://host/path HTTP/1.1)
    try:
        authority, path = parse_absolute_uri(target)
        host_s, port = split_host_port(authority, 80)
        domain_hits.update([host_s])
    except Exception:
        writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return

    # Rebuild request line with origin-form path (strip proxy absolute-URI)
    # Remove Proxy-Authorization header before forwarding
    try:
        lines = header_block.split(b"\r\n")
        out_headers = []
        for ln in lines:
            if ln[:19].lower() == b"proxy-authorization":
                continue
            out_headers.append(ln)
        new_head = method + b" " + path + b" " + version + b"\r\n" + b"\r\n".join(out_headers) + b"\r\n\r\n"
    except Exception:
        writer.close()
        await writer.wait_closed()
        active_conn -= 1
        return

    # Open remote and forward
    remote_w = None
    try:
        remote_r, remote_w = await asyncio.wait_for(asyncio.open_connection(host_s, port), timeout=TIMEOUT)
        # Nagle off for remote too
        try:
            rsock = remote_w.get_extra_info("socket")
            if rsock is not None:
                rsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except Exception:
            pass

        remote_w.write(new_head)
        await remote_w.drain()

        # Stream both directions
        t1 = asyncio.create_task(pipe_stream(reader, remote_w, True))
        t2 = asyncio.create_task(pipe_stream(remote_r, writer, False))
        await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    except Exception:
        try:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
    finally:
        try:
            if remote_w is not None:
                remote_w.close()
                await remote_w.wait_closed()
        except Exception:
            pass
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        active_conn -= 1

async def _serve():
    if USE_UVLOOP:
        try:
            import uvloop
            uvloop.install()
        except Exception:
            pass

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, lambda: None)
        except NotImplementedError:
            # Windows
            pass

    server = await asyncio.start_server(
        handle_client, HOST, PORT, reuse_port=True, start_serving=True, backlog=BACKLOG
    )

    addrs = ", ".join(str(s.getsockname()) for s in server.sockets or [])
    print(f"[proxy] Listening on {addrs} (uvloop={USE_UVLOOP})", flush=True)
    async with server:
        await server.serve_forever()

def run():
    asyncio.run(_serve())

if __name__ == "__main__":
    run()
