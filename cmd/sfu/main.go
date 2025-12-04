package main

import (
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/pion/ion/v2/internal/config"
	"github.com/pion/ion/v2/internal/logger"
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
	lf, err := logger.NewLoggerFactory(logger.Options{
		DefaultWriter: config.WriterStderr,
		Format:        config.LogFormatText,
		ScopeLevels: map[string]string{
			"sfu":    "debug",
			"signal": "error",
		},
		DefaultLevel: "debug",
	})
	logger := lf.ForScope("sfu-main")
	if err != nil {
		panic(err)
	}
	srv := sfu.NewSFUServer(lf)
	proto.RegisterSFUServiceServer(s, srv)
	reflection.Register(s)

	logger.Info("sfu worker running", "workerID", *workerID, "addr", lis.Addr(), "publicAddress", *publicAddress)

	if err := s.Serve(lis); err != nil {
		logger.Error("failed to serve", "err", err)
	}
}
