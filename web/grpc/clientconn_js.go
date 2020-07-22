// +build js,wasm

package grpc

import (
	"context"
)

// ClientConnInterface defines the functions clients need to perform unary and
// streaming RPCs.  It is implemented by *ClientConn, and is only intended to
// be referenced by generated code.
type ClientConnInterface interface {
	// Invoke performs a unary RPC and returns after the response is received
	// into reply.
	Invoke(ctx context.Context, method string, args interface{}, reply interface{}, opts ...CallOption) error
	// NewStream begins a streaming RPC.
	NewStream(ctx context.Context, desc *StreamDesc, method string, opts ...CallOption) (ClientStream, error)
}

type ClientConn struct {
        target string
}

// Dial creates a client connection to the target. The target string should
// be a URL with scheme HTTP or HTTPS, or a FQDN to infer the scheme.
func Dial(target string, opts ...DialOption) (*ClientConn, error) {
        return DialContext(context.Background(), target, opts...)
}

func DialContext(ctx context.Context, target string, opts ...DialOption) (conn *ClientConn, err error) {
        return &ClientConn{
                target: target,
        }, nil
}

func (cc *ClientConn) Close() error {
	return nil
}
