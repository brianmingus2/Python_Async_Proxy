
import os, multiprocessing as mp, signal, sys, time
import socket
import proxy

LISTEN_PORT = int(os.getenv("PROXY_LISTEN", "8888"))
UPSTREAM_HOST = os.getenv("UPSTREAM_HOST", "127.0.0.1").encode()
UPSTREAM_PORT = int(os.getenv("UPSTREAM_PORT", "8080"))
WORKERS = int(os.getenv("WORKERS", str(os.cpu_count() or 4)))
BUSY_POLL = int(os.getenv("SO_BUSY_POLL", "0"))
DEFER_ACC = int(os.getenv("DEFER_ACCEPT", "1"))
FASTOPEN = int(os.getenv("TCP_FASTOPEN", "0"))
CORK = int(os.getenv("TCP_CORK", "1"))

def worker(idx):
    p = proxy.SpliceProxy(LISTEN_PORT, UPSTREAM_HOST, UPSTREAM_PORT,
                          backlog=65535, reuseport=1, busy_poll=BUSY_POLL,
                          defer_acc=DEFER_ACC, fastopen_qlen=FASTOPEN, cork=CORK)
    p.run(max_events=8192, splice_len=1<<20, sleep_ns=0)

if __name__ == "__main__":
    procs = []
    for i in range(WORKERS):
        pid = os.fork()
        if pid == 0:
            os.sched_setaffinity(0, {i % (os.cpu_count() or 1)})
            worker(i)
            sys.exit(0)
        else:
            procs.append(pid)

    def shutdown(signum, frame):
        for pid in procs:
            try: os.kill(pid, signal.SIGTERM)
            except ProcessLookupError: pass
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    while True:
        time.sleep(1)
