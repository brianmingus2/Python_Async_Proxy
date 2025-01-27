from urllib.parse import urlparse
import collections
import asyncio
import base64
import signal
import json
import time
import sys

USER, PASS = 'username', 'password'
HOST, PORT = '127.0.0.1', 8888

# Time between requests for deduplication heuristic
# i.e. apple.com -> www.apple.com
WINDOW = 5

# Request timeout for domains that hang i.e. microsoft.com
TIMEOUT = 10

visits = {}
bw = 0
last_time = collections.defaultdict(float)

def format_bw(xfered):
    if xfered < 1024:
        return f"{xfered}B"
    elif xfered < 1024**2:
        return f"{xfered / 1024:.2f}KB"
    else:
        return f"{xfered / 1024**2:.2f}MB"

def canon(host):
    """Simplify domain to xyz.com"""
    parts = host.split('.')
    if len(parts) > 2:
        return '.'.join(parts[-2:])
    return host

def print_met():
    print("Metrics:")
    print(f"Bandwidth usage: {format_bw(bw)}")
    if visits:
        sorted_vis = sorted(visits.items(),
                            key=lambda item: item[1],
                            reverse=True)
        for dom, visit_cnt in sorted_vis:
            print(f"- {dom}: {visit_cnt} visit(s)")
    else:
        print("No visits.")

    sys.exit(0)

async def proxy(client_r, client_w):
    global bw
    try:
        data = await asyncio.wait_for(client_r.read(1024),
                                      timeout=TIMEOUT)

        if b'GET /metrics' in data:
            sorted_vis = sorted(visits.items(),
                                key=lambda item: item[1],
                                reverse=True)
            metrics_resp = {
                "bandwidth_usage": format_bw(bw),
                "top_sites": [
                    {"url": dom,
                     "visits": visit_cnt}
                    for dom, visit_cnt in sorted_vis]}
            client_w.write(
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: application/json\r\n\r\n" +
                json.dumps(metrics_resp).encode())

            await client_w.drain()
            return client_w.close()

        auth_head = base64.b64encode(f"{USER}:{PASS}".encode())
        if f'Proxy-Authorization: Basic {auth_head.decode()}' not in data.decode():
            client_w.write(
                b"HTTP/1.1 407 Proxy Auth Required\r\n"
                b"Proxy-Authenticate: Basic\r\n\r\n")
            return await client_w.drain()

        met, targ, _ = data.split(b' ')[:3]
        remote_r, remote_w = None, None
        dom = ""

        if met == b'CONNECT':
            host, port = targ.split(b':')
            dom = canon(host.decode())
            try:
                remote_r, remote_w = await asyncio.open_connection(host.decode(), int(port))
                client_w.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                await client_w.drain()
            except Exception as error:
                print(f"Error connecting to {host.decode()}:"
                      f"{int(port)}: {error}")
                client_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return await client_w.drain()
        else:
            parsed_url = urlparse(targ.decode())
            host = parsed_url.netloc
            dom = canon(host)
            try:
                remote_r, remote_w = await asyncio.open_connection(host, 80)
                remote_w.write(data)
                await remote_w.drain()
            except Exception as error:
                print(f"Error connecting to {host}:80: {error}")
                client_w.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                return await client_w.drain()

        # Update metrics
        cur_time = time.time()
        if cur_time - last_time[dom] > WINDOW:
            last_time[dom] = cur_time
            visits[dom] = visits.get(dom, 0) + 1

        async def relay(src_read, dest_write):
            global bw
            try:
                while True:
                    data_chunk = await asyncio.wait_for(src_read.read(4096), timeout=TIMEOUT)
                    if not data_chunk:
                        break
                    bw += len(data_chunk)
                    dest_write.write(data_chunk)
                    await asyncio.wait_for(dest_write.drain(), timeout=TIMEOUT)
            except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
                pass
            finally:
                dest_write.close()

        to_client = asyncio.create_task(relay(client_r, remote_w))
        to_remote = asyncio.create_task(relay(remote_r, client_w))
        await asyncio.gather(to_client, to_remote)
    except asyncio.TimeoutError:
        print("Timeout.")
    except Exception as error:
        print(f"Error: {error}")
    finally:
        client_w.close()

async def main():
    loop = asyncio.get_running_loop()

    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, print_met)

    server = await asyncio.start_server(proxy, HOST, PORT)
    async with server:
        print(f"Running on {HOST}:{PORT}")
        await server.serve_forever()

try:
    asyncio.run(main())
except KeyboardInterrupt:
    print_met()
