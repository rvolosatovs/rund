// Copyright 2021 Romans Volosatovs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package job runs arbitrary Linux processes in namespaces with cgroups.
package job

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/rjeczalik/notify"
)

// TODO: Make entropy configurable if necessary. That could be done via either:
// - SetEntropy method.
// - Specifying entropy as a field in job config.

// entropy is used for generation of ULIDs.
var entropy io.Reader = ulid.Monotonic(rand.Reader, 0)

// Job represents a job started via Start.
type Job struct {
	id  ulid.ULID
	cmd *exec.Cmd

	doneCh chan struct{}

	stoppedMu sync.RWMutex
	stopped   bool

	stdout string
	stderr string

	cgroup string
}

// Config represents the job configuration.
type Config struct {
	// Command to run.
	Command string
	// Args represent the command arguments.
	Args []string

	// MaxCPUBandwidth corresponds to `cpu.max`, which indicates how many time units the job may consume out of 100000.
	MaxCPUBandwidth *uint32

	// MaxMemoryUsageBytes corresponds to `memory.max`, which indicates memory usage hard limit in bytes.
	MaxMemoryUsageBytes *uint64

	// MaxRBPS corresponds to `rbps` field of `io.max`, which indicates max read bytes per second.
	MaxRBPS *uint64
	// MaxWBPS corresponds to `wbps` field of `io.max`, which indicates max write bytes per second.
	MaxWBPS *uint64
	// MaxRIOPS corresponds to `riops` field of `io.max`, which indicates max read IO operations per second.
	MaxRIOPS *uint64
	// MaxWIOPS corresponds to `wiops` field of `io.max`, which indicates max write IO operations per second.
	MaxWIOPS *uint64

	// RootFS is the path to root filesystem to use for `pivot_root`.
	RootFS string
	// CGroupFS is the path to cgroup2 filesystem.
	CGroupFS string
	// IODevices is a list of IO devices to use with `io.max`.
	IODevices []string

	// MakeExecutionArguments returns execution arguments to pass to `/proc/self/exe` given a fifoPath to trigger reexecution.
	// MakeExecutionArguments MUST be set before Start is called.
	// This is typically set from the main package.
	MakeExecutionArguments func(fifoPath string) []string
}

func createLogFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE, 0600)
	if err != nil {
		return err
	}
	return f.Close()
}

// Start starts the job specified by the configuration.
func Start(conf Config) (_ *Job, err error) {
	if conf.Command == "" {
		return nil, errors.New("command is empty")
	}
	if conf.MakeExecutionArguments == nil {
		return nil, errors.New("`MakeExecutionArguments` is nil")
	}

	id, err := ulid.New(ulid.Now(), entropy)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ULID: %w", err)
	}
	idStr := id.String()

	dir, err := ioutil.TempDir("", idStr)
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer func() {
		if err != nil {
			if err := os.RemoveAll(dir); err != nil {
				log.Printf("Failed to remove %q: %s", dir, err)
			}
		}
	}()

	fifoPath := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifoPath, 0600); err != nil {
		return nil, fmt.Errorf("failed to create FIFO file: %w", err)
	}

	cmd := exec.Command("/proc/self/exe", conf.MakeExecutionArguments(fifoPath)...)
	// See
	// - https://linux.die.net/man/2/clone
	// - https://linux.die.net/man/2/unshare
	// for documentation on the flags specified.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWIPC |
			syscall.CLONE_NEWNET |
			syscall.CLONE_NEWNS |
			syscall.CLONE_NEWPID |
			syscall.CLONE_NEWUTS,
		Unshareflags: syscall.CLONE_NEWNS,
		Pdeathsig:    syscall.SIGKILL, // ensure all children are killed on SIGKILL
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}
	defer func() {
		if err != nil {
			if err := cmd.Process.Kill(); err != nil {
				log.Printf("Failed to kill process: %s", err)
			}
		}
	}()

	fifo, err := os.OpenFile(fifoPath, os.O_WRONLY, 0600)
	if err != nil {
		return nil, fmt.Errorf("failed to open FIFO file: %w", err)
	}
	defer fifo.Close()

	stdoutPath := filepath.Join(dir, "stdout")
	if err := createLogFile(stdoutPath); err != nil {
		return nil, fmt.Errorf("failed to create stdout file: %w", err)
	}

	stderrPath := filepath.Join(dir, "stderr")
	if err := createLogFile(stderrPath); err != nil {
		return nil, fmt.Errorf("failed to create stderr file: %w", err)
	}

	if err := gob.NewEncoder(fifo).Encode(executionRequest{
		ID:     id,
		Config: conf,

		Stdout: stdoutPath,
		Stderr: stderrPath,
	}); err != nil {
		return nil, fmt.Errorf("failed to write execution request to FIFO file: %w", err)
	}
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		if err := cmd.Wait(); err != nil {
			log.Printf("Failed to wait for job %s to finish: %s", idStr, err)
		}
	}()
	return &Job{
		id:  id,
		cmd: cmd,

		doneCh: doneCh,

		stdout: stdoutPath,
		stderr: stderrPath,

		cgroup: filepath.Join(conf.CGroupFS, idStr),
	}, nil
}

// ID returns the job ID.
func (j *Job) ID() ulid.ULID {
	return j.id
}

// Wait waits waits until either the process finishes or context is done, whichever happens first.
func (j *Job) Wait(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-j.doneCh:
		return nil
	}
}

// Stop kills the job process and all children.
func (j *Job) Stop() error {
	j.stoppedMu.Lock()
	defer j.stoppedMu.Unlock()

	if j.stopped {
		return nil
	}
	j.stopped = true
	select {
	case <-j.doneCh:
		return nil
	default:
		// NOTE: Since job is started with Pdeathsig, this kills children as well.
		// NOTE(2): This potentially is in race condition with Wait call in the goroutine started by Start,
		// so we check for ErrProcessDone even though we acquired the lock.
		switch err := j.cmd.Process.Kill(); err {
		case nil, os.ErrProcessDone:
			return nil
		default:
			return err
		}
	}
}

// Status represents the status of the Job.
type Status struct {
	// ExitCode is the exit code of the exited process, or nil if it's still running.
	ExitCode *int

	// Killed indicates whether the job was killed.
	Killed bool
	// Stopped indicates whether the job was stopped via Stop.
	Stopped bool

	// UserTime represents the user CPU time of the exited process and its children.
	UserTime time.Duration
	// SystemTime represents the system CPU time of the exited process and its children.
	SystemTime time.Duration

	// The total amount of memory currently being used by the job cgroup and its descendants in bytes.
	MemoryCurrent uint64
}

// parseCPUTimeLine parses duration from a `cpu.stat` line.
func parseCPUTimeLine(b []byte) (time.Duration, error) {
	kv := bytes.Fields(b)
	if len(kv) != 2 {
		return 0, errors.New("line is not in '$field $value' format")
	}
	v, err := strconv.ParseInt(string(kv[1]), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("failed to parse %s into int64: %w", kv[1], err)
	}
	if v < 0 {
		return 0, fmt.Errorf("%d is negative", v)
	}
	if v > math.MaxInt64/int64(time.Microsecond) {
		return 0, fmt.Errorf("%d overflows time.Duration", v)
	}
	return time.Duration(v) * time.Microsecond, nil
}

type cpuStat struct {
	userTime   time.Duration
	systemTime time.Duration
}

func parseCPUStat(b []byte) (*cpuStat, error) {
	var (
		userTime   time.Duration
		systemTime time.Duration
	)
	for _, bl := range bytes.Split(b, []byte{'\n'}) {
		switch {
		case bytes.HasPrefix(bl, []byte("user_usec")):
			v, err := parseCPUTimeLine(bl)
			if err != nil {
				return nil, fmt.Errorf("failed to parse user_usec: %w", err)
			}
			userTime = v

		case bytes.HasPrefix(bl, []byte("system_usec")):
			v, err := parseCPUTimeLine(bl)
			if err != nil {
				return nil, fmt.Errorf("failed to parse system_usec: %w", err)
			}
			systemTime = v
		}
	}
	return &cpuStat{
		userTime:   userTime,
		systemTime: systemTime,
	}, nil
}

// Status returns the job status.
// For running jobs, the status is derived from cgroup data.
// For finished jobs, the status is derived from *os.ProcessState of the underlying command.
func (j *Job) Status() (*Status, error) {
	var (
		stopped       bool
		killed        bool
		exitCode      *int
		userTime      time.Duration
		systemTime    time.Duration
		memoryCurrent uint64
	)
	if j.cmd.ProcessState != nil {
		j.stoppedMu.RLock()
		stopped = j.stopped

		// NOTE: Lock is held here until `killed` value is known to prevent a situation where Stop is called
		// immediately after unlocking and the caller would receive a status, which would indicate that the job
		// was killed, but not stopped.
		c := j.cmd.ProcessState.ExitCode()
		if c < 0 {
			killed = true
		} else {
			exitCode = &c
		}
		j.stoppedMu.RUnlock()

		userTime = j.cmd.ProcessState.UserTime()
		systemTime = j.cmd.ProcessState.SystemTime()
	} else {
		cpuPath := filepath.Join(j.cgroup, "cpu.stat")
		b, err := ioutil.ReadFile(cpuPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %w", cpuPath, err)
		}
		st, err := parseCPUStat(b)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'cpu.stat': %w", err)
		}
		userTime = st.userTime
		systemTime = st.systemTime

		memPath := filepath.Join(j.cgroup, "memory.current")
		b, err = ioutil.ReadFile(memPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read %q: %w", memPath, err)
		}
		b = bytes.TrimSpace(b)
		v, err := strconv.ParseUint(string(b), 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse 'memory.current' value of %s into uint64: %w", b, err)
		}
		memoryCurrent = v
	}

	return &Status{
		Stopped:  stopped,
		Killed:   killed,
		ExitCode: exitCode,

		UserTime:   userTime,
		SystemTime: systemTime,

		MemoryCurrent: memoryCurrent,
	}, nil
}

// notifyBufSize is the size of inotify event channel buffer.
// Since HandleLog always reads the whole file, 1 is enough.
const notifyBufSize = 1

// HandleLog calls stdoutHandle for all contents in job stdout and
// calls stderrHandle for all contents in job stderr until either:
// - ctx is done
// - job is done
// HandleLog reads at most n bytes at a time.
// HandleLog watches for inotify events to track file changes internally.
func (j *Job) HandleLog(ctx context.Context, n uint, stdoutHandle, stderrHandle func(b []byte) error) error {
	stdoutCh := make(chan notify.EventInfo, notifyBufSize)
	if err := notify.Watch(j.stdout, stdoutCh, notify.Write); err != nil {
		return fmt.Errorf("failed to watch stdout file: %w", err)
	}
	defer notify.Stop(stdoutCh)

	stderrCh := make(chan notify.EventInfo, notifyBufSize)
	if err := notify.Watch(j.stderr, stderrCh, notify.Write); err != nil {
		return fmt.Errorf("failed to watch stderr file: %w", err)
	}
	defer notify.Stop(stderrCh)

	b := make([]byte, n)
	process := func(r io.Reader, name string, f func(b []byte) error) error {
		for {
			n, err := r.Read(b)
			if n > 0 {
				if err := f(b[:n]); err != nil {
					return err
				}
			}
			if err != nil && err != io.EOF {
				return fmt.Errorf("failed to read %s file: %w", name, err)
			}
			if err == io.EOF {
				return nil
			}
		}
	}

	stdout, err := os.Open(j.stdout)
	if err != nil {
		return fmt.Errorf("failed to open stdout file for reading: %w", err)
	}
	defer stdout.Close()

	processStdout := func() error {
		return process(stdout, "stdout", stdoutHandle)
	}
	if err := processStdout(); err != nil {
		return err
	}

	stderr, err := os.Open(j.stderr)
	if err != nil {
		return fmt.Errorf("failed to open stderr file for reading: %w", err)
	}
	defer stderr.Close()

	processStderr := func() error {
		return process(stderr, "stderr", stderrHandle)
	}
	if err := processStderr(); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case <-j.doneCh:
			if err := processStdout(); err != nil {
				return err
			}
			return processStderr()

		case e, ok := <-stdoutCh:
			if !ok {
				return errors.New("stdout event stream closed")
			}
			switch e.Event() {
			case notify.Write:
				if err := processStdout(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("invalid event received %s", e)
			}

		case e, ok := <-stderrCh:
			if !ok {
				return errors.New("stderr event stream closed")
			}
			switch e.Event() {
			case notify.Write:
				if err := processStderr(); err != nil {
					return err
				}
			default:
				return fmt.Errorf("invalid event received %s", e)
			}
		}
	}
}

// executionRequest is the request passed from parent to child via the FIFO file.
type executionRequest struct {
	// Stdout is the path to file to write stdout to.
	Stdout string
	// Stderr is the path to file to write stderr to.
	Stderr string

	Config

	// ID is the unique job identifier.
	ID ulid.ULID
}

// Execute reads an execution request from fifoPath and executes it.
// Execute will always create a cgroup with name identical to parsed ID
// and add the process to it.
// Execute is an internal function and is expected to be called by main package
// directly during reexecution triggered by Start.
func Execute(fifoPath string) error {
	fifo, err := os.Open(fifoPath)
	if err != nil {
		return fmt.Errorf("failed to open FIFO file: %w", err)
	}
	var req executionRequest
	if err := gob.NewDecoder(fifo).Decode(&req); err != nil {
		return fmt.Errorf("failed to read execution request from FIFO file: %w", err)
	}
	if err := fifo.Close(); err != nil {
		return fmt.Errorf("failed to close FIFO file: %w", err)
	}

	stdout, err := os.OpenFile(req.Stdout, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open stdout file for writing: %w", err)
	}
	defer stdout.Close()

	stderr, err := os.OpenFile(req.Stderr, os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		return fmt.Errorf("failed to open stderr file for writing: %w", err)
	}
	defer stderr.Close()

	idStr := req.ID.String()

	cgPath := filepath.Join(req.CGroupFS, idStr)
	if err := os.MkdirAll(cgPath, 0700); err != nil {
		return fmt.Errorf("failed to create cgroup: %w", err)
	}
	if v := req.Config.MaxCPUBandwidth; v != nil {
		if err := ioutil.WriteFile(filepath.Join(cgPath, "cpu.max"), []byte(strconv.FormatUint(uint64(*v), 10)), 0); err != nil {
			return fmt.Errorf("failed to write 'cpu.max': %w", err)
		}
	}
	if v := req.Config.MaxMemoryUsageBytes; v != nil {
		if err := ioutil.WriteFile(filepath.Join(cgPath, "memory.max"), []byte(strconv.FormatUint(*v, 10)), 0); err != nil {
			return fmt.Errorf("failed to write 'memory.max': %w", err)
		}
	}
	if req.Config.MaxRBPS != nil ||
		req.Config.MaxWBPS != nil ||
		req.Config.MaxRIOPS != nil ||
		req.Config.MaxWIOPS != nil {
		path := filepath.Join(cgPath, "io.max")
		buf := &bytes.Buffer{}
		for _, dev := range req.IODevices {
			buf.WriteString(dev)
			if v := req.Config.MaxRBPS; v != nil {
				fmt.Fprintf(buf, " rbps=%d", *v)
			}
			if v := req.Config.MaxWBPS; v != nil {
				fmt.Fprintf(buf, " wbps=%d", *v)
			}
			if v := req.Config.MaxRIOPS; v != nil {
				fmt.Fprintf(buf, " riops=%d", *v)
			}
			if v := req.Config.MaxWIOPS; v != nil {
				fmt.Fprintf(buf, " wiops=%d", *v)
			}
			if err := ioutil.WriteFile(path, buf.Bytes(), 0); err != nil {
				return fmt.Errorf("failed to write 'io.max': %w", err)
			}
			buf.Reset()
		}
	}
	if err := ioutil.WriteFile(filepath.Join(cgPath, "cgroup.procs"), []byte(strconv.Itoa(os.Getpid())), 0); err != nil {
		return fmt.Errorf("failed to add process to cgroup: %w", err)
	}

	if err := syscall.Sethostname([]byte(idStr)); err != nil {
		return fmt.Errorf("failed to set hostname: %w", err)
	}
	hostRootPath := filepath.Join(req.RootFS, "hostroot")
	if err := os.MkdirAll(hostRootPath, 0700); err != nil {
		return fmt.Errorf("failed to create host root filesystem path: %w", err)
	}

	if err := syscall.Mount("proc", filepath.Join(req.RootFS, "proc"), "proc", 0, ""); err != nil {
		return fmt.Errorf("failed to mount procfs: %w", err)
	}
	if err := syscall.Mount("/dev", filepath.Join(req.RootFS, "dev"), "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("failed to mount devfs: %w", err)
	}

	if err := syscall.Mount(req.RootFS, req.RootFS, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("failed to bind-mount root file system: %w", err)
	}
	if err := syscall.PivotRoot(req.RootFS, hostRootPath); err != nil {
		return fmt.Errorf("failed to pivot root file system: %w", err)
	}
	if err := syscall.Chdir("/"); err != nil {
		return fmt.Errorf("failed to chdir to '/': %w", err)
	}
	if err := syscall.Unmount("/hostroot", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("failed to unmount host root file system: %w", err)
	}

	// Call command via `/bin/sh` to ensure environment is correctly set up, e.g. `/etc/profile` is loaded.
	cmd := exec.Command(filepath.Join("/bin", "sh"), append([]string{"--login", "-c", req.Command}, req.Args...)...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}
