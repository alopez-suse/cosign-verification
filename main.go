package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/google/go-containerregistry/pkg/name"
	"google.golang.org/grpc"

	grpcapi "github.com/alopez-suse/cosign-verification/grpcapi"
	verification "github.com/alopez-suse/cosign-verification/verification"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	grpcapi.UnimplementedVerificationServer
}

func (s *server) VerifySignatures(ctx context.Context, in *grpcapi.VerifySignaturesRequest) (*grpcapi.VerifySignaturesReply, error) {
	digest, err := name.NewDigest(in.GetImageReference())
	if err != nil {
		panic(err)
	}
	signatures := verification.GetSignaturesForDigest(digest)
	return &grpcapi.VerifySignaturesReply{Signed: verification.DigestSignedByKey(digest, signatures, in.GetPublicKey())}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	grpcapi.RegisterVerificationServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
