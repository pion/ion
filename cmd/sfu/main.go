package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/pion/ion/v2/internal/sfu"
	"github.com/pion/ion/v2/internal/sfu/proto"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

func main() {
	var (
		grpcPort      = flag.Int("grpc-port", 50051, "gRPC listen port")
		workerID      = flag.String("id", "worker-1", "worker ID")
		publicAddress = flag.String("public-address", "ws://localhost:8081", "public signaling base URL")
	)
	flag.Parse()

	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *grpcPort))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	srv := sfu.NewSFUServer()
	proto.RegisterSFUServiceServer(s, srv)
	reflection.Register(s)

	log.Printf("Worker %s listening on %s (public: %s)", *workerID, lis.Addr(), *publicAddress)

	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
