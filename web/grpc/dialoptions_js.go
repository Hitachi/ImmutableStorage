// +build js,wasm

package grpc

import (
	"google.golang.org/grpc/credentials"
)

// DialOption configures how we set up the connection.
type DialOption func(*dialOptions)

// dialOptions configure a Dial call. dialOptions are set by the DialOption
// values passed to Dial.
type dialOptions struct {
}

// WithInsecure returns a DialOption which disables transport security for this
// ClientConn. Note that transport security is required unless WithInsecure is
// set.
func WithInsecure() DialOption {
	var f DialOption
	return f
}

// WithTransportCredentials returns a DialOption which configures a connection
// level security credentials (e.g., TLS/SSL). This should not be used together
// with WithCredentialsBundle.
func WithTransportCredentials(creds credentials.TransportCredentials) DialOption {
	var f DialOption
	return f
}
