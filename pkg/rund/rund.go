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

// Package rund contains the rund gRPC server implementation.
package rund

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"math"
	"net"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
	"github.com/rvolosatovs/rund/pkg/job"
	"github.com/rvolosatovs/rund/pkg/pb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type authJob struct {
	*job.Job

	sans map[string]struct{}
}

type Server struct {
	pb.UnimplementedJobControllerServer

	// ulid.ULID -> *authJob
	jobs sync.Map

	Address      string
	ClientCAs    *x509.CertPool
	Certificates []tls.Certificate

	RootFS    string
	CGroupFS  string
	IODevices []string

	// MakeExecutionArguments returns execution arguments to pass to `/proc/self/exe` given a fifoPath to trigger reexecution.
	// MakeExecutionArguments MUST be set before Start is called.
	// This is typically set from the main package.
	MakeExecutionArguments func(fifoPath string) []string
}

func unwrapUint32(v *wrapperspb.UInt32Value) *uint32 {
	if v == nil {
		return nil
	}
	return &v.Value
}

func unwrapUint64(v *wrapperspb.UInt64Value) *uint64 {
	if v == nil {
		return nil
	}
	return &v.Value
}

func tlsInfo(ctx context.Context) (*credentials.TLSInfo, error) {
	p, ok := peer.FromContext(ctx)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "no peer in request context")
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, grpc.Errorf(codes.Unauthenticated, "no TLS info in request context")
	}
	return &info, nil
}

func (s *Server) Start(ctx context.Context, req *pb.JobStartRequest) (*pb.JobIdentifier, error) {
	ti, err := tlsInfo(ctx)
	if err != nil {
		return nil, err
	}
	sans := map[string]struct{}{}
	for _, cert := range ti.State.PeerCertificates {
		for _, name := range cert.DNSNames {
			sans[name] = struct{}{}
		}
	}

	j, err := job.Start(job.Config{
		Command: req.Name,
		Args:    req.Args,

		MaxCPUBandwidth: unwrapUint32(req.MaxCpuBandwidth),

		MaxMemoryUsageBytes: unwrapUint64(req.MaxMemoryUsage),

		MaxRBPS:  unwrapUint64(req.MaxRbps),
		MaxWBPS:  unwrapUint64(req.MaxWbps),
		MaxRIOPS: unwrapUint64(req.MaxRiops),
		MaxWIOPS: unwrapUint64(req.MaxWiops),

		RootFS:    s.RootFS,
		CGroupFS:  s.CGroupFS,
		IODevices: s.IODevices,

		MakeExecutionArguments: s.MakeExecutionArguments,
	})
	if err != nil {
		return nil, err
	}
	id := j.ID()
	s.jobs.Store(id, &authJob{
		Job:  j,
		sans: sans,
	})
	return &pb.JobIdentifier{
		Ulid: id.String(),
	}, nil
}

func errNotFound(id string) error {
	return grpc.Errorf(codes.NotFound, "job identified by '%s' not found", id)
}

func (s *Server) job(ctx context.Context, pbID *pb.JobIdentifier) (*job.Job, error) {
	ti, err := tlsInfo(ctx)
	if err != nil {
		return nil, err
	}

	idStr := pbID.GetUlid()
	id, err := ulid.Parse(idStr)
	if err != nil {
		return nil, grpc.Errorf(codes.InvalidArgument, "failed to parse '%s' into a ULID: %s", idStr, err)
	}

	// NOTE: NotFound error is returned to avoid leaking data about existing jobs to unauthorized clients.

	v, ok := s.jobs.Load(id)
	if !ok {
		return nil, errNotFound(idStr)
	}
	j, ok := v.(*authJob)
	if !ok {
		log.Printf("Invalid job type stored under ID %s", idStr)
		return nil, errNotFound(idStr)
	}

	for _, cert := range ti.State.PeerCertificates {
		for _, name := range cert.DNSNames {
			if _, ok := j.sans[name]; ok {
				return j.Job, nil
			}
		}
	}
	return nil, errNotFound(idStr)
}

func jobStatus(j *job.Job) (*pb.JobStatus, error) {
	st, err := j.Status()
	if err != nil {
		return nil, grpc.Errorf(codes.Internal, "failed to query job status: %s", err)
	}
	var exitCode *wrapperspb.UInt32Value
	if st.ExitCode != nil {
		c := *st.ExitCode
		if c < 0 || c > math.MaxUint32 {
			return nil, grpc.Errorf(codes.Internal, "invalid exit code received")
		}
		exitCode = &wrapperspb.UInt32Value{
			Value: uint32(c),
		}
	}
	return &pb.JobStatus{
		Stopped:       st.Stopped,
		Killed:        st.Killed,
		ExitCode:      exitCode,
		UserTime:      durationpb.New(st.UserTime),
		SystemTime:    durationpb.New(st.SystemTime),
		MemoryCurrent: st.MemoryCurrent,
	}, nil
}

func (s *Server) Stop(ctx context.Context, id *pb.JobIdentifier) (*pb.JobStatus, error) {
	j, err := s.job(ctx, id)
	if err != nil {
		return nil, err
	}
	if err := j.Stop(); err != nil {
		return nil, grpc.Errorf(codes.Internal, "failed to stop job: %s", err)
	}
	return jobStatus(j)
}

func (s *Server) Status(ctx context.Context, id *pb.JobIdentifier) (*pb.JobStatus, error) {
	j, err := s.job(ctx, id)
	if err != nil {
		return nil, err
	}
	return jobStatus(j)
}

func (s *Server) Log(id *pb.JobIdentifier, stream pb.JobController_LogServer) error {
	ctx := stream.Context()
	j, err := s.job(ctx, id)
	if err != nil {
		return err
	}
	return j.HandleLog(
		ctx,
		func(b []byte) error {
			return stream.Send(&pb.JobLog{
				Stdout: b,
			})
		},
		func(b []byte) error {
			return stream.Send(&pb.JobLog{
				Stderr: b,
			})
		},
	)
}

// Serve serves gRPC `JobController` service until ctx.Done().
func (s *Server) Serve(ctx context.Context) error {
	// TODO: Validate server configuration

	// TLS config based on:
	// - https://www.ssl.com/guide/ssl-best-practices/
	// - https://safecurves.cr.yp.to/
	// - https://github.com/golang/go/blob/23ffb5b9ae9e6e313df648d8bf6ab7b8f5ff0cf1/src/crypto/tls/common.go#L1493-L1498
	// NOTE: The config is quite restrictive and requirements may be softened if compatibility with clients is an issue.
	// TODO: Possibly optimize the cipher suite choice based on hardware same as done in stdlib if necessary.
	grpcSrv := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates:             s.Certificates,
			ClientCAs:                s.ClientCAs,
			ClientAuth:               tls.RequireAndVerifyClientCert,
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS13,
			CurvePreferences: []tls.CurveID{
				tls.CurveP521,
				tls.X25519,
			},
		})),
	)
	pb.RegisterJobControllerServer(grpcSrv, s)

	grpcLis, err := net.Listen("tcp", s.Address)
	if err != nil {
		return fmt.Errorf("failed to listen for TCP on '%s': %w", s.Address, err)
	}

	go func() {
		<-ctx.Done()

		// TODO: Make this timeout configurable.
		const gracefulStopTimeout = 10 * time.Second
		defer time.AfterFunc(gracefulStopTimeout, func() {
			log.Printf("Graceful stop did not succeed in %s, forcing gRPC server stop...", gracefulStopTimeout)
			grpcSrv.Stop()
		}).Stop()
		log.Println("Attempt to gracefully stop the gRPC server...")
		grpcSrv.GracefulStop()
	}()
	if err := grpcSrv.Serve(grpcLis); err != nil {
		return fmt.Errorf("failed to serve gRPC: %w", err)
	}
	return nil
}
