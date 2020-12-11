// +build js,wasm

package grpc

// CallOption configures a Call before it starts or extracts information from
// a Call after it completes.
type CallOption interface {
        // before is called before the call is sent to any server.  If before
        // returns a non-nil error, the RPC fails with that error.
        before(*callInfo) error

        // after is called after the call has completed.  after cannot return an
        // error, so any failures should be reported via output parameters.
        after(*callInfo)
}

type callInfo struct {
}

func defaultCallInfo() *callInfo {
        return &callInfo{}
}

// The SupportPackageIsVersion variables are referenced from generated protocol
// buffer files to ensure compatibility with the gRPC version used.  The latest
// support package version is 6.
//
// Older versions are kept for compatibility. They may be removed if
// compatibility cannot be maintained.
//
// These constants should not be referenced from any other code.
const (
	SupportPackageIsVersion3 = true
	SupportPackageIsVersion4 = true
	SupportPackageIsVersion5 = true
	SupportPackageIsVersion6 = true
)
