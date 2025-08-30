# proxy.pyx
# Cython-optimized HTTPS CONNECT proxy with Basic Auth + metrics.

# distutils: language = c
# cython: language_level=3, boundscheck=False, wraparound=False, initializedcheck=False, infer_types=True

from libc.stdlib cimport atoi
import asyncio
import base64
import json
import os
import signal
import sys
from collections import Counter

# --------------------
# Config
# --------------------
cdef str USER = "username"
cdef str PASS = "password"
cdef str HOST = "127.0.0.1"
cdef int PORT = 8888
cdef int TIMEOUT = 10
cdef int BUF_SIZE = 65536
cdef str DEFAULT_BACKEND_HOST = "127.0.0.1"
cdef int DEFAULT_BACKEND_PORT = 80

cdef str INDEX_PATH1 = "/mnt/data/index.html"
cdef str INDEX_PATH2 = "index.html"

# --------------------
# Metrics
# --------------------
visits = Counter()
cdef unsigned long long bw_up = 0
cdef unsigned long long bw_down = 0
cdef unsigned long long total_conns = 0
cdef unsigned long long active_conns = 0
cdef unsigned long long total_reqs = 0

# --------------------
# Precomputed constants
# --------------------
cdef bytes B_CRLFCRLF = b"\r\n\r\n"
cdef bytes B_CRLF = b"\r\n"
cdef bytes B_GET = b"GET"
cdef bytes B_CONNECT = b"CONNECT"
cdef bytes B_PROXY_AUTH = b"proxy-authorization"
cdef bytes B_HOST = b"host"
cdef bytes B_HTTP_200_CONN = b"HTTP/1.1 200 Connection Established\r\n\r\n"
cdef bytes B_HTTP_407 = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n"
cdef bytes B_HTTP_400 = b"HTTP/1.1 400 Bad Request\r\n\r\n"
cdef bytes B_HTTP_502 = b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
cdef bytes B_HTTP_404 = b"HTTP/1.1 404 Not Found\r\n\r\n"
cdef bytes B_HTTP_200 = b"HTTP/1.1 200 OK\r\n"
cdef bytes B_CT_JSON = b"Content-Type: application/json\r\n"
cdef bytes B_CT_HTML = b"Content-Type: text/html; charset=utf-8\r\n"
cdef bytes B_CL = b"Content-Length: "

cdef bytes EXPECTED_AUTH = b"Basic " + base64.b64encode(f"{USER}:{PASS}".encode("utf-8"))

# --------------------
# Utilities
# --------------------
cdef inline str _canon(str host):
    cdef list parts = host.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return host

cdef inline bytes _fmt_bytes(unsigned long long x) except *:
    if x < 1024:
        return (str(x) + " B").encode("ascii")
    elif x < 1024*1024:
        return (f"{x/1024:.2f} KB").encode("ascii")
    elif x < 1024*1024*1024:
        return (f"{x/1024/1024:.2f} MB").encode("ascii")
    else:
        return (f"{x/1024/1024/1024:.2f} GB").encode("ascii")

cdef bytes _load_index():
    cdef str path = INDEX_PATH1 if os.path.exists(INDEX_PATH1) else INDEX_PATH2
    if os.path.exists(path):
        with open(path, "rb") as f:
            return f.read()
    return b""

cdef inline dict _parse_headers(bytes raw) except *:
    cdef dict h = {}
    cdef list lines = raw.split(b"\r\n")
    cdef bytes line, k, v
    cdef int i
    for line in lines:
        if not line:
            continue
        i = line.find(b":")
        if i <= 0:
            continue
        k = line[:i].strip().lower()
        v = line[i+1:].strip()
        h[k] = v
    return h

def check_auth(dict headers) -> bint:
    cdef bytes v = <bytes>headers.get(B_PROXY_AUTH, b"")
    if not v:
        return False
    if v[:6].lower() != b"basic ":
        return False
    return v == EXPECTED_AUTH

cdef inline tuple _parse_request_line(bytes reqline) except *:
    cdef int s1 = reqline.find(b" ")
    if s1 <= 0: raise ValueError("bad request line")
    cdef int s2 = reqline.find(b" ", s1+1)
    if s2 <= s1: raise ValueError("bad request line")
    return reqline[:s1], reqline[s1+1:s2], reqline[s2+1:]

cdef inline tuple _split_host_port_bytes(bytes hostport, int default_port) except *:
    cdef int i = hostport.rfind(b":")
    if i >= 0:
        return hostport[:i].decode("utf-8"), atoi(hostport[i+1:].decode("ascii"))
    else:
        return hostport.decode("utf-8"), default_port

cdef inline tuple _extract_host_port_from_absolute_uri(bytes target) except *:
    cdef int scheme_end = target.find(b"://")
    if scheme_end <= 0:
        return "", 0, target
    cdef int host_start = scheme_end + 3
    cdef int slash = target.find(b"/", host_start)
    cdef bytes hostport
    cdef bytes path_qs
    if slash < 0:
        hostport = target[host_start:]
        path_qs = b"/"
    else:
        hostport = target[host_start:slash]
        path_qs = target[slash:] if slash >= 0 else b"/"
    cdef tuple hp = _split_host_port_bytes(hostport, 80)
    return hp[0], hp[1], path_qs

# --------------------
# Core proxy logic
# --------------------
async def _relay(reader, writer, bint count_up):
    global bw_up, bw_down
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(BUF_SIZE), timeout=TIMEOUT)
            if not chunk:
                break
            if count_up:
                bw_up += len(chunk)
            else:
                bw_down += len(chunk)
            writer.write(chunk)
            await writer.drain()
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass

async def _handle_connect(client_r, client_w, bytes hostport):
    global active_conns
    cdef str host
    cdef int port
    cdef str dom
    cdef object remote_r
    cdef object remote_w
    try:
        host, port = _split_host_port_bytes(hostport, 443)
        dom = _canon(host)
        visits.update([dom])
        remote_r, remote_w = await asyncio.open_connection(host, port)
    except Exception:
        client_w.write(B_HTTP_502)
        await client_w.drain()
        visits.update(["failed"])
        return
    client_w.write(B_HTTP_200_CONN)
    await client_w.drain()
    active_conns += 1
    to_server = asyncio.create_task(_relay(client_r, remote_w, True))
    to_client = asyncio.create_task(_relay(remote_r, client_w, False))
    await asyncio.gather(to_server, to_client)
    active_conns -= 1
    visits.update(["successful"])

async def _handle_http(client_r, client_w,
                       bytes method, bytes target, bytes version, dict headers, bytes raw_head):
    global active_conns
    cdef str host_s = ""
    cdef int port_i = 80
    cdef bytes path_qs = b"/"
    cdef bytes host_hdr = b""
    cdef str dom
    cdef object remote_r
    cdef object remote_w
    cdef bytes reqline

    if target and target[:1] == b"/":
        if target == b"/metrics":
            body = {
                "bandwidth_up": _fmt_bytes(bw_up).decode("ascii"),
                "bandwidth_down": _fmt_bytes(bw_down).decode("ascii"),
                "total_connections": int(total_conns),
                "active_connections": int(active_conns),
                "total_requests": int(total_reqs),
                "successful": int(visits.get("successful", 0)),
                "failed": int(visits.get("failed", 0)),
            }
            body_bytes = json.dumps(body).encode("utf-8")
            resp = B_HTTP_200 + B_CT_JSON + B_CL + str(len(body_bytes)).encode("ascii") + B_CRLF + B_CRLF + body_bytes
            client_w.write(resp)
            await client_w.drain()
            return
        if target == b"/index.html":
            data = _load_index()
            if data:
                resp = B_HTTP_200 + B_CT_HTML + B_CL + str(len(data)).encode("ascii") + B_CRLF + B_CRLF + data
                client_w.write(resp)
                await client_w.drain()
                return
            else:
                client_w.write(B_HTTP_404)
                await client_w.drain()
                return

    try:
        host_s, port_i, path_qs = _extract_host_port_from_absolute_uri(target)
    except Exception:
        host_s, port_i, path_qs = "", 0, target

    if not host_s:
        host_hdr = <bytes>headers.get(B_HOST, b"")
        if host_hdr:
            host_s, port_i = _split_host_port_bytes(host_hdr, 80)
        else:
            host_s = DEFAULT_BACKEND_HOST
            port_i = DEFAULT_BACKEND_PORT

    dom = _canon(host_s)
    visits.update([dom])

    try:
        remote_r, remote_w = await asyncio.open_connection(host_s, port_i)
    except Exception:
        client_w.write(B_HTTP_502)
        await client_w.drain()
        visits.update(["failed"])
        return

    reqline = method + b" " + (path_qs if path_qs else b"/") + b" " + version + B_CRLF
    remote_w.write(reqline)
    for k, v in headers.items():
        if k == B_PROXY_AUTH:
            continue
        remote_w.write(k + b": " + v + B_CRLF)
    remote_w.write(B_CRLF)
    await remote_w.drain()

    active_conns += 1
    to_origin = asyncio.create_task(_relay(client_r, remote_w, True))
    to_client = asyncio.create_task(_relay(remote_r, client_w, False))
    await asyncio.gather(to_origin, to_client)
    active_conns -= 1
    visits.update(["successful"])

async def _handle_client(client_r, client_w):
    global total_conns, total_reqs
    total_conns += 1
    visits.update(["total"])
    try:
        head = await asyncio.wait_for(client_r.readuntil(B_CRLFCRLF), timeout=TIMEOUT)
    except Exception:
        client_w.write(B_HTTP_400)
        await client_w.drain()
        client_w.close()
        return
    try:
        idx = head.find(B_CRLF)
        reqline = head[:idx]
        raw_headers = head[idx+2:-4]
        method, target, version = _parse_request_line(reqline)
    except Exception:
        client_w.write(B_HTTP_400)
        await client_w.drain()
        client_w.close()
        return
    headers = _parse_headers(raw_headers)
    total_reqs += 1
    if not check_auth(headers):
        client_w.write(B_HTTP_407)
        await client_w.drain()
        client_w.close()
        return
    if method == B_CONNECT:
        await _handle_connect(client_r, client_w, target)
    else:
        await _handle_http(client_r, client_w, method, target, version, headers, head)

# --------------------
# Entrypoint
# --------------------
async def _run():
    loop = asyncio.get_running_loop()
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception:
        pass
    server = await asyncio.start_server(_handle_client, HOST, PORT, reuse_address=True, reuse_port=True)
    print(f"[proxy] Listening on ('{HOST}', {PORT})")
    async with server:
        await server.serve_forever()

def run():
    asyncio.run(_run())

if __name__ == "__main__":
    run()
