A solution to the C10K problem in Pure Python.

This is an HTTP/HTTPS CONNECT proxy written in async Python, which has been Cythonized.

## System Tuning

In order to run the C10K benchmark on Linux you may need to increase the number of allowed file handles.

## Benchmark Environment

For benchmarking purposes a tuned local Apache webserver was used as the backend. It served the small index.html included in this repo from `/var/www/html/`.

## Installation

- The Python distribution used was Miniforge. https://github.com/conda-forge/miniforge

- After installing Miniforge, run `mamba install cython`.

- To build `proxy.pyx` run `python setup.py build_ext --inplace`.

- On Ubuntu, run `sudo apt update` followed by `sudo apt -y install curl wrk siege`.

## Running the Benchmark

To run the benchmark:

- Make sure Apache is serving `index.html`.
- Start the proxy with `python -c "import proxy"`.
- Run `bash bench.sh`

## Results

The output will include the results of `wrk` and `siege`. On the test system, which is Ubuntu LTS on VMWare Workstation Pro, it gets up to 4550 requests per second, which is almost halfway to C10K.

**wrk**

```Running 30s test @ http://127.0.0.1:8888/index.html
  1 threads and 100 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency    21.54ms    2.12ms  38.92ms   80.87%
    Req/Sec     4.57k   399.68     5.42k    55.67%
  Latency Distribution
     50%   21.18ms
     75%   22.30ms
     90%   23.82ms
     99%   29.35ms
  136655 requests in 30.03s, 63.21MB read
  Non-2xx or 3xx responses: 136655
Requests/sec:   4549.94
Transfer/sec:      2.10MB
```

**siege**

```{	"transactions":			      124230,
	"availability":			      100.00,
	"elapsed_time":			       29.74,
	"data_transferred":		       35.90,
	"response_time":		        0.02,
	"transaction_rate":		     4177.20,
	"throughput":			        1.21,
	"concurrency":			       99.83,
	"successful_transactions":	           0,
	"failed_transactions":		           0,
	"longest_transaction":		        0.04,
	"shortest_transaction":		        0.00}
```

