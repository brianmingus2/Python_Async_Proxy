A solution to the C10K problem in Pure Python.

This is an HTTP/HTTPS CONNECT proxy written in async Python, which has been Cythonized.

## System Tuning

In order to run the C10K benchmark on Linux you may need to increase the number of allowed file handles. There are a variety of other ways to tune the system as well.

## Benchmark Environment

For benchmarking purposes a tuned local Apache webserver was used as the backend. It served the small index.html included in this repo from `/var/www/html/`.

## Installation

- The Python distribution used was Miniforge. https://github.com/conda-forge/miniforge

- After installing Miniforge, run `mamba install cython`.

- If building Python from source run `pip3 install cython setuptools`.

- If building Python from source there are compiler flags available such as `--enable-optimizations --enable-experimental-jit` which improve performance.

- To build `proxy.pyx` run `python setup.py build_ext --inplace`.

- On Ubuntu, run `sudo apt update` followed by `sudo apt -y install curl wrk siege`.

## Running the Benchmark

To run the benchmark:

- Make sure Apache is serving `index.html`.
- Start the proxy with `python -c "import proxy"`.
- Run `bash bench.sh`.

## Results

The output will include the results of `wrk` and `siege`. On the test system, which is Ubuntu LTS on VMWare Workstation Pro, it gets up to 4550 requests per second, which is almost halfway to C10K.

**wrk**

```
Running 30s test @ http://127.0.0.1:8888/index.html
  1 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    20.62ms    1.38ms  38.09ms   80.11%
    Req/Sec     4.78k   295.64     5.51k    81.67%
  Latency Distribution
     50%   20.47ms
     75%   21.10ms
     90%   22.00ms
     99%   25.41ms
  142800 requests in 30.02s, 66.05MB read
  Non-2xx or 3xx responses: 142800
Requests/sec:   4756.53
Transfer/sec:      2.20MB
```

**siege**

```
	"transactions":			      131096,
	"availability":			      100.00,
	"elapsed_time":			       29.69,
	"data_transferred":		       37.88,
	"response_time":		        0.02,
	"transaction_rate":		     4415.49,
	"throughput":			        1.28,
	"concurrency":			       99.82,
	"successful_transactions":	           0,
	"failed_transactions":		           0,
	"longest_transaction":		        0.04,
	"shortest_transaction":		        0.00
```





🔥 Updating README for commit streak...
🔥 Updating README for commit streak...
🔥 Updating README for commit streak...
🔥 Updating README for commit streak...
🔥 Updating README for commit streak...
🔥 Updating README for commit streak...
