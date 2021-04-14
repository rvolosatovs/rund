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

// Package cli provides internal CLI utilities.
package cli

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

func init() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
}

// LoadCredentials reads and parses a public/private key pair from a pair of files using tls.LoadX509KeyPair,
// reads caFile and sets up a *x509.NewCertPool with parsed certificate added via AppendCertsFromPEM.
// See documentation on respective functions in standard library for more info.
func LoadCredentials(caFile, certFile, keyFile string) ([]tls.Certificate, *x509.CertPool, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to load TLS key pair from certificate at '%s' and key at '%s': %w", certFile, keyFile, err)
	}

	b, err := ioutil.ReadFile(caFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read CA certificate at '%s': %w", caFile, err)
	}
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(b) {
		return nil, nil, fmt.Errorf("failed to add CA certificate to pool")
	}
	return []tls.Certificate{cert}, certPool, nil
}

type Command interface {
	Parse(*flag.FlagSet, ...string) error
	Run() error
}

type Subcommand struct {
	Command
	*flag.FlagSet
}

func (cmd *Subcommand) Parse(args ...string) error {
	return cmd.Command.Parse(cmd.FlagSet, args...)
}

func Main(f func(string) (*Subcommand, bool), names ...string) {
	if len(names) == 0 {
		panic("`names` cannot be empty")
	}
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [%s]\n", os.Args[0], strings.Join(names, "|"))
		flag.PrintDefaults()
	}
	if len(os.Args) < 2 || os.Args[1] == "" {
		fmt.Fprintf(flag.CommandLine.Output(), "Subcommand must be specified\n")
		flag.Usage()
		os.Exit(1)
	}

	arg := os.Args[1]
	cmd, ok := f(arg)
	if !ok {
		switch arg {
		case "help", "-h", "-help", "--help":
			flag.Usage()
			os.Exit(0)

		default:
			fmt.Fprintf(flag.CommandLine.Output(), "Invalid subcommand '%s'\n", arg)
			flag.Usage()
			os.Exit(1)
		}
		panic("unreachable")
	}
	if err := cmd.Command.Parse(cmd.FlagSet, os.Args[2:]...); err != nil {
		fmt.Fprintf(flag.CommandLine.Output(), "Failed to parse subcommand arguments: %s\n", err)
		cmd.Usage()
		os.Exit(1)
	}
	if err := cmd.Run(); err != nil {
		log.Fatalf("Failed to run subcommand: %s", err)
	}
}
