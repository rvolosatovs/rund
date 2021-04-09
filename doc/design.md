# Run daemon

`rund` allows remote execution of arbitrary processes (jobs) on a Linux machine.

## Internal server design

Internally, the server will uniquely identify jobs using [ULIDs](https://github.com/ulid/spec) and maintain a hashmap mapping a ULID to the job. Note, that since an in-memory hashmap is used, potential scaling of the service would not be possible as-is; if that was necessary, the instances could share this internal structure via a key-value database, for example Redis.

`stdout` and `stderr` of each job will be written to temporary files. If logs are requested by the client, the server will then read logs from the temporary files - this approach would simplify implementation by letting the OS handle most of the functionality required for storage and concurrent reads.

Note, that simply writing logs to a in-memory buffer could potentially run out of memory. In case it is guaranteed that the output of run commands will be small, the implementation could use an in-memory buffer instead, which would be even simpler than writing to a file.

A better implementation could use a combination of both for best performance and memory efficiency, but implementing such solution is out of scope.

## Resource management

The following cgroup2 controller options will be configurable per-process:

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

A TLS configuration optimized for security will be used and derived by utilizing the best practices from following resources:
- [ssl.com best practices](https://www.ssl.com/guide/ssl-best-practices/)
- [Mozilla server side TLS guidelines](https://wiki.mozilla.org/Security/Server_Side_TLS)
- [safecurves.cr.yp.to](https://safecurves.cr.yp.to/)
- [Go standard library](https://github.com/golang/go/blob/23ffb5b9ae9e6e313df648d8bf6ab7b8f5ff0cf1/src/crypto/tls/common.go#L1493-L1498)

Proposed server TLS config in Go:
```go
tls.Config{
	ClientAuth:               tls.RequireAndVerifyClientCert,
	PreferServerCipherSuites: true,
	MinVersion:               tls.VersionTLS13,
	CurvePreferences: []tls.CurveID{
		tls.CurveP521,
		tls.X25519,
	},
```

For the purpose of this task secure TLS certificates will be generated locally via `openssl` and checked into the repository for simplicity.
A self-signed root CA certificate will be provided, along client and server certificates singed by the root CA.

All certificates will use P521 curve with SHA512 signatures.

Example CA certificate:
```bash
$ openssl x509 -in ca.pem -text --noout
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            3b:96:76:89:01:54:0f:54:6f:3b:ef:16:db:8f:d3:01:db:e5:5c:54
        Signature Algorithm: ecdsa-with-SHA512
        Issuer: CN = local CA
        Validity
            Not Before: Apr  6 18:52:21 2021 GMT
            Not After : Apr  6 18:52:21 2022 GMT
        Subject: CN = local CA
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (521 bit)
                pub:
                    04:01:df:ad:c0:86:41:5f:a4:f2:de:e6:01:78:9d:
                    24:0c:59:8e:e3:60:fc:16:57:b4:85:84:ab:16:19:
                    20:a9:e7:b7:fd:d4:05:65:f5:90:08:45:ee:f0:4d:
                    3e:62:19:7e:76:d7:bc:6c:64:ae:96:35:d6:02:83:
                    a5:e6:1f:f5:ee:f9:66:00:5d:3b:41:de:0e:97:2d:
                    53:57:02:93:03:fa:bf:0b:b9:e7:2c:aa:2a:2d:eb:
                    6d:57:6b:e3:76:dd:7d:12:6e:a8:1a:e3:2e:1a:e2:
                    f8:fd:b7:c6:61:4d:90:98:f9:38:74:a8:27:4b:18:
                    dd:45:b4:62:41:c8:ab:d9:88:bd:51:61:3a
                ASN1 OID: secp521r1
                NIST CURVE: P-521
        X509v3 extensions:
            X509v3 Subject Key Identifier: 
                24:03:D3:BE:CB:EF:8D:5D:E8:EB:3E:B4:26:65:2F:96:4F:FB:E1:A0
            X509v3 Authority Key Identifier: 
                keyid:24:03:D3:BE:CB:EF:8D:5D:E8:EB:3E:B4:26:65:2F:96:4F:FB:E1:A0

            X509v3 Basic Constraints: critical
                CA:TRUE
    Signature Algorithm: ecdsa-with-SHA512
         30:81:87:02:41:24:de:04:42:a2:5d:ed:fa:16:db:ad:6d:33:
         37:70:33:40:dd:a9:14:0b:ec:33:0a:04:85:0e:02:04:f0:f6:
         fd:6f:68:b0:b6:28:77:32:0b:24:ce:5e:14:f4:28:d4:b0:96:
         83:e6:12:bd:34:22:73:89:80:db:a8:1c:30:ff:e4:1d:02:42:
         01:7d:87:da:7a:28:51:43:c0:2a:9d:4b:73:52:8b:11:9b:59:
         45:4b:5d:fd:62:0f:b1:92:d5:a9:f3:3e:ce:01:e9:db:5c:13:
         54:5b:57:1d:06:6f:8c:54:13:40:29:0c:df:fc:6f:14:07:54:
         f0:eb:18:88:77:a6:bd:7b:eb:5f:04:02
```

## Authorization

- Clients will only be able to access jobs started by the server instance (i.e. the jobs contained in internal hashmap).
- Client will be able to only access jobs actually started by the client. This will be achieved by recording [SANs](https://tools.ietf.org/html/rfc5280#section-4.2.1.6) client certificate specified when starting the job and only allow later job access to clients presenting a certificate containing at least one of the SANs present in the certificate used for the start request.
- The fact that clients need to know the ULID of the job to access it provides additional, lightweight security measure.

Following security measures could be implemented, but are left out for simplicity:
- Maintain a whitelist of commands allowed to be started by the client.

## API

> See https://github.com/rvolosatovs/rund/blob/9cad2266f3b2e806c27077053ef1432eb22c98c8/api/api.proto#L10-L160 for proposed gRPC API implementing the below endpoints.

The server will expose 4 gRPC endpoints

### Start

`Start` RPC starts a job given command, arguments and resource control parameters and returns a ULID that can be used to access the started job later.

The RPC allows several cgroup2 controller parameters to be specified, which will be used for resource control. Limits are only set if specified in the request. In order to have a way for the server to determine whether a numeric value is specified by the client or not, all numeric values are wrapped in standard protobuf wrappers.

Once an authorized (see above) start request is received, the server will:
1. Generate a ULID.
2. Create two temporary files to write `stdout` and `stderr` to respectively.
3. (stretch goal) Create a new temporary directory, which will be used as filesystem root for the job.
4. Create a FIFO file in a temporary directory, which will be used for communicating with the child process.
5. Call `/proc/self/exe` in separate PID, networking and mount namespaces with UID and GID mappings. A command line flag indicating that reexecution is taking place will be specified, value of which will be equal to the FIFO file path created earlier.
6. Write execution parameters (command, arguments, resource management parameters) into the FIFO file as binary [gob](https://golang.org/pkg/encoding/gob/)-encoded data.
7. Store the job under the ULID in the internal hashmap.

The reexecuted binary will:
1. Setup cgroups.
2. Generate and set hostname.
3. (stretch goal) Bridge networking interfaces from the host.
4. (stretch goal) Chroot into the directory generated by the server.
5. Set working directory to `/`.
6. Mount procfs.

After the process is started, the `Start` RPC will immediately return, while the process will be left running in background.

### Stop

`Stop` RPC kills the running job and returns its status.

Once a stop request is received, the server will:
1. Attempt to find the process in the internal hashmap by the ULID.
2. Kill the process by signaling `SIGKILL`.

### Status

`Status` RPC returns the status of a job.

Status message returned will consist of:
- field indicating, whether job was stopped
- field indicating, whether job was killed
- exit code of the job, if exited
- `user_time` and `system_time` provided by cgroup2 `cpu.stat`
- `memory_current` provided by cgroup2 `memory.current`

> See https://github.com/rvolosatovs/rund/blob/9cad2266f3b2e806c27077053ef1432eb22c98c8/api/api.proto#L22-L90 for suggested protobuf message

Once a status request is received, the server will:
1. Attempt to find the process in the internal hashmap by the ULID.
2. Read contents of relevant cgroup files under `/sys/fs/cgroup/pids/$name`

### Log

`Log` RPC streams job logs.

Once a log request is received, the server will:
1. Attempt to find the process in the internal hashmap by the ULID.
2. Read and stream the contents of `stderr` and `stdout` files associated with the job.
3. Subscribe to `inotify` events of the two files.
4. Whenever either of the files is written to, read the file and stream read contents.

## CLI 

### `rund` server

The server CLI will provide 2 subcommands.

#### `rund serve`

`rund serve` will serve `JobController` gRPC service.

The following flags will be provided by `rund serve`:
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

`rund execute` will execute the job passed on command-line in a manner described above under `Start` RPC behavior.

The following flags will be provided by `rund execute`:
```
  -fifo string
    	path to FIFO file
```

### `runc` client

The client CLI will be a simple thin wrapper around the `JobController` service gRPC client and provide 4 subcommands.

#### `runc start`

`runc start` will call `JobController.Start` RPC and print received ULID to `stdout` on success.

The following flags will be provided by `runc start`:
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

`runc stop` will call `JobController.Stop` RPC and print received status to `stdout` as JSON object on success.

The following flags will be provided by `runc stop`:
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

`runc status` will call `JobController.Status` RPC and print received status to `stdout` as JSON object on success.

The following flags will be provided by `runc status`:
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

`runc log` will call `JobController.Log` RPC, stream `stdout` of the job to `stdout` and stream `stderr` of the job to `stderr`.

The following flags will be provided by `runc log`:
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

Example usage will look as follows:
```bash
    id="$(runc start -max_memory_usage 10000000 -max_rbps 42 ls /)" # this will start the process and print ID to stdout
    runc status "${id}" # this will print JSON-formatted JobStatus to stdout 
    runc logs "${id}" # this will print logs line-by-line to stdout until ^C is received
    runc stop "${id}" # this will stop the job and print the exit code to stdout
```
