// +build js,wasm

package grpc

// Server is a gRPC server to serve RPC requests.
type Server struct{}

type ServiceRegistrar interface {
	RegisterService(desc *ServiceDesc, impl interface{})
}

func (s *Server) RegisterService(sd *ServiceDesc, ss interface{}) {}

