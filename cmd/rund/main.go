package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/rvolosatovs/rund/cmd/internal/cli"
	"github.com/rvolosatovs/rund/pkg/job"
	"github.com/rvolosatovs/rund/pkg/rund"
)

var defaultIODeviceStr = func() string {
	glob := filepath.Join("/sys", "devices", "virtual", "block", "*", "dev")
	paths, err := filepath.Glob(glob)
	if err != nil {
		return ""
	}
	devs := make([]string, 0, len(paths))
	for _, p := range paths {
		dev, err := ioutil.ReadFile(p)
		if err != nil {
			continue
		}
		devs = append(devs, string(bytes.TrimSpace(dev)))
	}
	return strings.Join(devs, ",")
}()

type Serve struct {
	Address *string

	CAFile   *string
	CertFile *string
	KeyFile  *string

	CGroupFS  *string
	IODevices *string
}

func NewServeSubcommand() *cli.Subcommand {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	return &cli.Subcommand{
		Command: &Serve{
			Address: fs.String("addr", ":8000", "gRPC endpoint address"),

			CAFile:   fs.String("ca", "tls/ca.pem", "path to CA certificate"),
			CertFile: fs.String("cert", "tls/server.pem", "path to TLS certificate"),
			KeyFile:  fs.String("key", "tls/server-key.pem", "path to TLS key"),

			CGroupFS:  fs.String("cgroupFS", filepath.Join("/sys", "fs", "cgroup"), "path to cgroup2 file system"),
			IODevices: fs.String("io_devices", defaultIODeviceStr, "comma-separated block devices to use for IO limits"),
		},
		FlagSet: fs,
	}
}

func (cmd *Serve) Parse(fs *flag.FlagSet, args ...string) error {
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

	case *cmd.CGroupFS == "":
		return errors.New("`cgroupfs` cannot be empty")

	case *cmd.IODevices == "":
		return errors.New("`io_devices` cannot be empty")
	}
	return nil
}

func (cmd *Serve) Run() error {
	certs, certPool, err := cli.LoadCredentials(*cmd.CAFile, *cmd.CertFile, *cmd.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load mTLS credentials: %w", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	log.Printf("Starting gRPC server at '%s'...", *cmd.Address)
	if err := (&rund.Server{
		Address:      *cmd.Address,
		Certificates: certs,
		ClientCAs:    certPool,

		CGroupFS:  *cmd.CGroupFS,
		IODevices: strings.Split(*cmd.IODevices, ","),

		MakeExecutionArguments: func(fifoPath string) []string {
			return []string{"execute", "-fifo", fifoPath}
		},
	}).Serve(ctx); err != nil {
		return fmt.Errorf("failed to start gRPC server: %w", err)
	}
	<-ctx.Done()
	return nil
}

type Execute struct {
	FIFOFile *string
}

func NewExecuteSubcommand() *cli.Subcommand {
	fs := flag.NewFlagSet("execute", flag.ExitOnError)
	return &cli.Subcommand{
		Command: &Execute{
			FIFOFile: fs.String("fifo", "", "path to FIFO file"),
		},
		FlagSet: fs,
	}
}

func (cmd *Execute) Parse(fs *flag.FlagSet, args ...string) error {
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case *cmd.FIFOFile == "":
		return errors.New("`fifo` cannot be empty")
	}
	return nil
}

func (cmd *Execute) Run() error {
	return job.Execute(*cmd.FIFOFile)
}

func main() {
	cli.Main(func(arg string) (*cli.Subcommand, bool) {
		switch arg {
		case "serve", "serv", "ser", "se", "s":
			return NewServeSubcommand(), true

		case "execute", "execut", "execu", "exec", "exe", "ex", "e":
			return NewExecuteSubcommand(), true
		}
		return nil, false
	},
		"serve",
		"execute",
	)
}
