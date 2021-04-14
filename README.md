# rund

`rund` ("Run Daemon") allows remote execution of arbitrary processes (jobs) on a Linux machine.

## Resource management

The following cgroup2 controller options are configurable per-process:

- `cpu.max` - The maximum CPU bandwidth limit, which indicates how many time units the job may consume out of `100000`.
- `memory.max` - Memory usage hard limit in bytes.
- `io.max` - BPS and IOPS based IO limit.
    - `rbps` - Max read bytes per second.
    - `wbps` - Max write bytes per second.
    - `riops` - Max read IO operations per second.
    - `wiops` - Max write IO operations per second.

> NOTE: See the following for documentation on various cgroup2 controllers and their options:
> - https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#controllers

## Authentication

Both parties authenticate to each other using mTLS.

A TLS configuration optimized for security are used and derived by utilizing the best practices from following resources:
- [ssl.com best practices](https://www.ssl.com/guide/ssl-best-practices/)
- [Mozilla server side TLS guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [safecurves.cr.yp.to](https://safecurves.cr.yp.to/)
- [Go standard library](https://github.com/golang/go/blob/23ffb5b9ae9e6e313df648d8bf6ab7b8f5ff0cf1/src/crypto/tls/common.go#L1493-L1498)

For the sake of example secure TLS certificates are generated locally via `openssl` and checked into the repository.
A self-signed root CA certificate is provided, along client and server certificates singed by the root CA.

All certificates use P521 curve with SHA512 signatures.

## Authorization

- Clients are only able to access jobs started by the server instance.
- Clients are only able to access jobs actually started by them. This is achieved by recording [SANs](https://tools.ietf.org/html/rfc5280#section-4.2.1.6) client certificate specified when starting the job and only allow later job access to clients presenting a certificate containing at least one of the SANs present in the certificate used for the start request.
- The fact that clients need to know the ULID of the job to access it provides additional, lightweight security measure.

## API

The server exposes 4 gRPC endpoints

### Start

`Start` RPC starts a job given command, arguments and resource control parameters and returns a ULID that can be used to access the started job later.

The RPC allows several cgroup2 controller parameters to be specified, which are used for resource control. Limits are only set if specified in the request. In order to have a way for the server to determine whether a numeric value is specified by the client or not, all numeric values are wrapped in standard protobuf wrappers.

After the process is started, the `Start` RPC will immediately return, while the process are left running in background.

### Stop

`Stop` RPC kills the running job and returns its status.

### Status

`Status` RPC returns the status of a job.

### Log

`Log` RPC streams job logs.

## CLI 

### `rund` server

The server CLI provides 2 subcommands.

#### `rund serve`

`rund serve` serves `JobController` gRPC service.

The following flags are provided by `rund serve`:
```
  -addr string
    	gRPC endpoint address (default ":8000")
  -ca string
    	path to CA certificate (default "tls/ca.pem")
  -cert string
    	path to TLS certificate (default "tls/server.pem")
  -key string
    	path to TLS key (default "tls/server-key.pem")
```

#### `rund execute`

`rund execute` executes the job passed on command-line in a manner described above under `Start` RPC behavior.

The following flags are provided by `rund execute`:
```
  -fifo string
    	path to FIFO file
```

### `runc` client

The client CLI is a simple thin wrapper around the `JobController` service gRPC client and provides 4 subcommands.

#### `runc start`

`runc start` calls `JobController.Start` RPC and prints received ULID to `stdout` on success.

The following flags are provided by `runc start`:
```
  -addr string
    	gRPC endpoint address (default "localhost:8000")
  -ca string
    	path to CA certificate (default "tls/ca.pem")
  -cert string
    	path to TLS certificate (default "tls/client.pem")
  -key string
    	path to TLS key (default "tls/client-key.pem")
  -max_cpu_bandwidth uint
    	maximum CPU bandwidth limit, which indicates how many time units the job may consume out of 100000
  -max_memory_usage uint
    	memory usage hard limit in bytes
  -max_rbps uint
    	max read bytes per second
  -max_riops uint
    	max read IO opetations per second
  -max_wbps uint
    	max read bytes per second
  -max_wiops uint
    	max read IO opetations per second
```

#### `runc stop`

`runc stop` calls `JobController.Stop` RPC and prints received status to `stdout` as JSON object on success.

The following flags are provided by `runc stop`:
```
  -addr string
    	gRPC endpoint address (default "localhost:8000")
  -ca string
    	path to CA certificate (default "tls/ca.pem")
  -cert string
    	path to TLS certificate (default "tls/client.pem")
  -key string
    	path to TLS key (default "tls/client-key.pem")
```

#### `runc status`

`runc status` calls `JobController.Status` RPC and prints received status to `stdout` as JSON object on success.

The following flags are provided by `runc status`:
```
  -addr string
    	gRPC endpoint address (default "localhost:8000")
  -ca string
    	path to CA certificate (default "tls/ca.pem")
  -cert string
    	path to TLS certificate (default "tls/client.pem")
  -key string
    	path to TLS key (default "tls/client-key.pem")
```

#### `runc log`

`runc log` calls `JobController.Log` RPC, streams `stdout` of the job to `stdout` and streams `stderr` of the job to `stderr`.

The following flags are provided by `runc log`:
```
  -addr string
    	gRPC endpoint address (default "localhost:8000")
  -ca string
    	path to CA certificate (default "tls/ca.pem")
  -cert string
    	path to TLS certificate (default "tls/client.pem")
  -key string
    	path to TLS key (default "tls/client-key.pem")
```

Example usage is as follows:
```bash
    id="$(runc start -max_memory_usage 10000000 -max_rbps 42 ls /)" # this will start the process and print ID to stdout
    runc status "${id}" # this will print JSON-formatted JobStatus to stdout 
    runc logs "${id}" # this will print logs line-by-line to stdout until ^C is received
    runc stop "${id}" # this will stop the job and print the exit code to stdout
```
