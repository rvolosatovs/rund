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

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/rvolosatovs/rund/cmd/internal/cli"
	"github.com/rvolosatovs/rund/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type command struct {
	Address *string

	CAFile   *string
	CertFile *string
	KeyFile  *string
}

func newCommand(fs *flag.FlagSet) *command {
	return &command{
		Address: fs.String("addr", "localhost:8000", "gRPC endpoint address"),

		CAFile:   fs.String("ca", "tls/ca.pem", "path to CA certificate"),
		CertFile: fs.String("cert", "tls/client.pem", "path to TLS certificate"),
		KeyFile:  fs.String("key", "tls/client-key.pem", "path to TLS key"),
	}
}

func (cmd *command) Parse(fs *flag.FlagSet, args ...string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *cmd.Address == "":
		return errors.New("`addr` cannot be empty")

	case *cmd.CAFile == "":
		return errors.New("`ca` cannot be empty")

	case *cmd.CertFile == "":
		return errors.New("`cert` cannot be empty")

	case *cmd.KeyFile == "":
		return errors.New("`key` cannot be empty")
	}
	return nil
}

func (cmd *command) withClient(f func(context.Context, pb.JobControllerClient) error) error {
	certs, certPool, err := cli.LoadCredentials(*cmd.CAFile, *cmd.CertFile, *cmd.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load mTLS credentials: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	conn, err := grpc.DialContext(ctx, *cmd.Address,
		grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			Certificates: certs,
			RootCAs:      certPool,
			MinVersion:   tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521,
				tls.X25519,
			},
		})),
	)
	if err != nil {
		return fmt.Errorf("failed to dial server at '%s': %w", *cmd.Address, err)
	}
	defer conn.Close()
	return f(ctx, pb.NewJobControllerClient(conn))
}

type Start struct {
	*command

	Name string
	Args []string

	MaxCPUBandwidth *uint64

	MaxMemoryUsage *uint64

	MaxRBPS  *uint64
	MaxWBPS  *uint64
	MaxRIOPS *uint64
	MaxWIOPS *uint64
}

const (
	minCPUBandwidthLimit = 1000
	maxCPUBandwidthLimit = 100000
)

func NewStartSubcommand() *cli.Subcommand {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s %s [<flags>] <cmd> [<args>] \n", os.Args[0], fs.Name())
		fs.PrintDefaults()
	}
	return &cli.Subcommand{
		Command: &Start{
			command: newCommand(fs),

			MaxCPUBandwidth: fs.Uint64("max_cpu_bandwidth", 0, fmt.Sprintf("maximum CPU bandwidth limit, which indicates how many time units the job may consume out of %d", maxCPUBandwidthLimit)),

			MaxMemoryUsage: fs.Uint64("max_memory_usage", 0, "memory usage hard limit in bytes"),

			MaxRBPS:  fs.Uint64("max_rbps", 0, "max read bytes per second"),
			MaxWBPS:  fs.Uint64("max_wbps", 0, "max read bytes per second"),
			MaxRIOPS: fs.Uint64("max_riops", 0, "max read IO opetations per second"),
			MaxWIOPS: fs.Uint64("max_wiops", 0, "max read IO opetations per second"),
		},
		FlagSet: fs,
	}
}

func (cmd *Start) Parse(fs *flag.FlagSet, args ...string) error {
	if err := cmd.command.Parse(fs, args...); err != nil {
		return err
	}
	switch {
	case *cmd.MaxCPUBandwidth != 0 &&
		(*cmd.MaxCPUBandwidth < minCPUBandwidthLimit || *cmd.MaxCPUBandwidth > maxCPUBandwidthLimit):
		return fmt.Errorf("`max_cpu_bandwidth` must be in range [%d;%d]", minCPUBandwidthLimit, maxCPUBandwidthLimit)
	}
	name := fs.Arg(0)
	if name == "" {
		return errors.New("name cannot be empty")
	}
	cmd.Name = name
	cmd.Args = fs.Args()[1:]
	return nil
}

func wrapUint32(v uint32) *wrapperspb.UInt32Value {
	if v == 0 {
		return nil
	}
	return &wrapperspb.UInt32Value{
		Value: v,
	}
}

func wrapUint64(v uint64) *wrapperspb.UInt64Value {
	if v == 0 {
		return nil
	}
	return &wrapperspb.UInt64Value{
		Value: v,
	}
}

func (cmd *Start) Run() error {
	return cmd.withClient(func(ctx context.Context, cl pb.JobControllerClient) error {
		id, err := cl.Start(ctx, &pb.JobStartRequest{
			Name: cmd.Name,
			Args: cmd.Args,

			MaxCpuBandwidth: wrapUint32(uint32(*cmd.MaxCPUBandwidth)),

			MaxMemoryUsage: wrapUint64(*cmd.MaxMemoryUsage),

			MaxRbps: wrapUint64(*cmd.MaxRBPS),
			MaxWbps: wrapUint64(*cmd.MaxWBPS),

			MaxRiops: wrapUint64(*cmd.MaxRIOPS),
			MaxWiops: wrapUint64(*cmd.MaxWIOPS),
		})
		if err != nil {
			return fmt.Errorf("failed to call JobController.Start: %w", err)
		}
		if _, err := fmt.Fprintf(os.Stdout, "%s\n", id.Ulid); err != nil {
			return fmt.Errorf("failed to write identifier to stdout: %w", err)
		}
		return nil
	})
}

type idCommand struct {
	*command

	ID string
}

func newIDSubcommand(fs *flag.FlagSet) *idCommand {
	fs.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s %s <id> \n", os.Args[0], fs.Name())
		fs.PrintDefaults()
	}
	return &idCommand{
		command: newCommand(fs),
	}
}

func (cmd *idCommand) Parse(fs *flag.FlagSet, args ...string) error {
	if err := cmd.command.Parse(fs, args...); err != nil {
		return err
	}
	id := fs.Arg(0)
	if id == "" {
		return errors.New("id cannot be empty")
	}
	if len(fs.Args()) > 1 {
		return errors.New("command takes exactly 1 argument")
	}
	cmd.ID = id
	return nil
}

func (cmd *idCommand) Identifier() *pb.JobIdentifier {
	return &pb.JobIdentifier{
		Ulid: cmd.ID,
	}
}

var jsonEncoder = json.NewEncoder(os.Stdout)

type Stop struct{ *idCommand }

func NewStopSubcommand() *cli.Subcommand {
	fs := flag.NewFlagSet("stop", flag.ExitOnError)
	return &cli.Subcommand{
		Command: &Stop{idCommand: newIDSubcommand(fs)},
		FlagSet: fs,
	}
}

func (cmd *Stop) Run() error {
	return cmd.withClient(func(ctx context.Context, cl pb.JobControllerClient) error {
		st, err := cl.Stop(ctx, cmd.Identifier())
		if err != nil {
			return fmt.Errorf("failed to call JobController.Stop: %w", err)
		}
		if err := jsonEncoder.Encode(st); err != nil {
			return fmt.Errorf("failed to write status to stdout: %w", err)
		}
		return nil
	})
}

type Status struct{ *idCommand }

func NewStatusSubcommand() *cli.Subcommand {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	return &cli.Subcommand{
		Command: &Status{idCommand: newIDSubcommand(fs)},
		FlagSet: fs,
	}
}

func (cmd *Status) Run() error {
	return cmd.withClient(func(ctx context.Context, cl pb.JobControllerClient) error {
		st, err := cl.Status(ctx, cmd.Identifier())
		if err != nil {
			return fmt.Errorf("failed to call JobController.Status: %w", err)
		}
		if err := jsonEncoder.Encode(st); err != nil {
			return fmt.Errorf("failed to write status to stdout: %w", err)
		}
		return nil
	})
}

type Log struct{ *idCommand }

func NewLogSubcommand() *cli.Subcommand {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	return &cli.Subcommand{
		Command: &Log{idCommand: newIDSubcommand(fs)},
		FlagSet: fs,
	}
}

func (cmd *Log) Run() error {
	return cmd.withClient(func(ctx context.Context, cl pb.JobControllerClient) error {
		s, err := cl.Log(ctx, cmd.Identifier())
		if err != nil {
			return fmt.Errorf("failed to call JobController.Log: %w", err)
		}
		streamCtx := s.Context()
		for {
			select {
			case <-streamCtx.Done():
				return streamCtx.Err()
			default:
				l, err := s.Recv()
				if err != nil {
					if err == io.EOF {
						return nil
					}
					return fmt.Errorf("failed to receive log line on stream: %w", err)
				}
				if b := l.GetStdout(); len(b) > 0 {
					if _, err := fmt.Fprintf(os.Stdout, "%s", b); err != nil {
						return fmt.Errorf("failed to write log line to stdout: %w", err)
					}
				}
				if b := l.GetStderr(); len(b) > 0 {
					if _, err := fmt.Fprintf(os.Stderr, "%s", b); err != nil {
						return fmt.Errorf("failed to write log line to stderr: %w", err)
					}
				}
			}
		}
	})
}

func main() {
	cli.Main(func(arg string) (*cli.Subcommand, bool) {
		switch arg {
		case "start", "star":
			return NewStartSubcommand(), true

		case "stop", "sto":
			return NewStopSubcommand(), true

		case "status", "statu", "stat":
			return NewStatusSubcommand(), true

		case "log", "lo", "l":
			return NewLogSubcommand(), true
		}
		return nil, false
	},
		"start",
		"status",
		"stop",
		"log",
	)
}
