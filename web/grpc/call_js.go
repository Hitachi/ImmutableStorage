// +build js,wasm

package grpc

import (
	"context"
	"encoding/binary"
	"encoding/base64"
	"bytes"
	"bufio"
	"net/http"
	"strings"
	"strconv"
	"time"
	"errors"
	"io"
//	"fmt"

	spb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
//	"encoding/hex"
//	"reflect"
)

// Copied from grpc-wasm
// https://github.com/johanbrandhorst/grpc-wasm/blob/master/clientconn.go
// Invoke sends the RPC request on the wire and returns after response is
// received.  This is typically called by generated code.
//
// All errors returned by Invoke are compatible with the status package.
func (cc *ClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...CallOption) error {
	b, err := proto.Marshal(args.(proto.Message))
	if err != nil {
		return status.Error(codes.Internal, err.Error())
	}

	bufHeader := make([]byte, 5)

//	fmt.Printf("log: b (len=%d):%s\n%s\n", len(b), reflect.TypeOf(b), hex.Dump(b))
	// Write length of b into buf
	binary.BigEndian.PutUint32(bufHeader[1:], uint32(len(b)))

	//	fmt.Printf("log: method=%s\n", method)
	endpoint := cc.target + method
	req, err := http.NewRequest(
		"POST",
		endpoint,
		bytes.NewBuffer(append(bufHeader, b...)),
	)
	if err != nil {
		return status.Error(codes.Unavailable, err.Error())
	}


	var resp *http.Response

	req = req.WithContext(ctx)
	addHeaders(req)
	resp, err = http.DefaultClient.Do(req)

	if err != nil {
		//		fmt.Printf("log: http.Do: error: %s\n", err)
		return status.Error(codes.Internal, err.Error())
	}
	defer resp.Body.Close()

	st := statusFromHeaders(resp.Header)
	if st.Code() != codes.OK {
		//fmt.Printf("log: error response: %s\n", st.Err())
		return st.Err()
	}

	msgHeader := make([]byte, 5)
	for {
		_, err := resp.Body.Read(msgHeader)
		if err != nil {
			// fmt.Printf("log: could not get header: %s\n", err)
			return status.Error(codes.Internal, err.Error())
		}

//		fmt.Printf("log: header = %02x %02x %02x %02x %02x\n", msgHeader[0], msgHeader[1], msgHeader[2], msgHeader[3], msgHeader[4])
		// 1 in MSB signifies that this is the trailer. Break loop.
		// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md#protocol-differences-vs-grpc-over-http2
		if msgHeader[0]>>7 == 1 {
			break
		}

		msgLen := binary.BigEndian.Uint32(msgHeader[1:])

		msg := make([]byte, msgLen)

		var getLen uint32
		for getLen = 0; getLen < msgLen; {
			readLen, err := resp.Body.Read(msg[getLen:])
			if err != nil {
				//fmt.Printf("log: read error: %s\n", err)
				return status.Error(codes.Internal, err.Error())
			}
			getLen += uint32(readLen)
		}
		err = proto.Unmarshal(msg, reply.(proto.Message))
		if err != nil {
			//fmt.Printf("log: unexpected message format: %s\n", err)
			return status.Error(codes.Internal, err.Error())
		}
	}

	if msgHeader[0]&1 == 0 {
		trailers, err := readTrailers(resp.Body)
		if err != nil {
			//			fmt.Printf("log: trailers error: %s\n", err)
			return status.Error(codes.Internal, err.Error())
		}
		st = statusFromHeaders(trailers)
	} else {
		// fmt.Printf("log: compressed trailer")
		// TODO(johanbrandhorst): Support compressed trailers
	}

	return st.Err()
}

// Invoke sends the RPC request on the wire and returns after response is
// received.  This is typically called by generated code.
//
// DEPRECATED: Use ClientConn.Invoke instead.
func Invoke(ctx context.Context, method string, args, reply interface{}, cc *ClientConn, opts ...CallOption) error {
	return cc.Invoke(ctx, method, args, reply, opts...)
}

func addHeaders(req *http.Request) {
	// TODO: Add more headers
	// https://github.com/grpc/grpc-go/blob/590da37e2dfb4705d8ebd9574ce4cb75295d9674/transport/http2_client.go#L356
	req.Header.Add("content-type", "application/grpc-web+proto")
	req.Header.Add("x-grpc-web", "1")
	if dl, ok := req.Context().Deadline(); ok {
		timeout := dl.Sub(time.Now())
		req.Header.Add("grpc-timeout", encodeTimeout(timeout))
	}
	md, ok := metadata.FromOutgoingContext(req.Context())
	if ok {
		for h, vs := range md {
			for _, v := range vs {
				req.Header.Add(h, v)
			}
		}
	}
}

const maxTimeoutValue int64 = 100000000 - 1

// Copied from grpc-go
// http_util.go

// div does integer division and round-up the result. Note that this is
// equivalent to (d+r-1)/r but has less chance to overflow.
func div(d, r time.Duration) int64 {
	if m := d % r; m > 0 {
		return int64(d/r + 1)
	}
	return int64(d / r)
}

// TODO(zhaoq): It is the simplistic and not bandwidth efficient. Improve it.
func encodeTimeout(t time.Duration) string {
	if t <= 0 {
		return "0n"
	}
	if d := div(t, time.Nanosecond); d <= maxTimeoutValue {
		return strconv.FormatInt(d, 10) + "n"
	}
	if d := div(t, time.Microsecond); d <= maxTimeoutValue {
		return strconv.FormatInt(d, 10) + "u"
	}
	if d := div(t, time.Millisecond); d <= maxTimeoutValue {
		return strconv.FormatInt(d, 10) + "m"
	}
	if d := div(t, time.Second); d <= maxTimeoutValue {
		return strconv.FormatInt(d, 10) + "S"
	}
	if d := div(t, time.Minute); d <= maxTimeoutValue {
		return strconv.FormatInt(d, 10) + "M"
	}
	// Note that maxTimeoutValue * time.Hour > MaxInt64.
	return strconv.FormatInt(div(t, time.Hour), 10) + "H"
}

// Copied from grpc-go
// https://github.com/grpc/grpc-go/blob/b94ea975f3beb73799fac17cc24ee923fcd3cb5c/transport/http_util.go#L213
func decodeBinHeader(v string) ([]byte, error) {
	if len(v)%4 == 0 {
		// Input was padded, or padding was not necessary.
		return base64.StdEncoding.DecodeString(v)
	}
	return base64.RawStdEncoding.DecodeString(v)
}

func readTrailers(in io.Reader) (http.Header, error) {
	s := bufio.NewScanner(in)
	trailers := http.Header{}
	for s.Scan() {
		v := s.Text()
		kv := strings.SplitN(v, ":", 2)
		// fmt.Printf("log: len(kev)=%d v=%s\n", len(kv), v)
		if len(kv) != 2 {
			return nil, errors.New("malformed header: " + v)
		}
		trailers.Add(kv[0], kv[1])
	}

	return trailers, s.Err()
}

func statusFromHeaders(h http.Header) *status.Status {
	details := h.Get("grpc-status-details-bin")
	if details != "" {
		b, err := decodeBinHeader(details)
		if err != nil {
			return status.New(codes.Internal, "malformed grps-status-details-bin header: "+err.Error())
		}
		s := &spb.Status{}
		err = proto.Unmarshal(b, s)
		if err != nil {
			return status.New(codes.Internal, "malformed grps-status-details-bin header: "+err.Error())
		}
		return status.FromProto(s)
	}
	sh := h.Get("grpc-status")
	if sh != "" {
		val, err := strconv.Atoi(sh)
		if err != nil {
			return status.New(codes.Internal, "malformed grpc-status header: "+err.Error())
		}
		return status.New(codes.Code(val), h.Get("grpc-message"))
	}
	return status.New(codes.OK, "")
}

func combine(o1 []CallOption, o2 []CallOption) []CallOption {
	// we don't use append because o1 could have extra capacity whose
	// elements would be overwritten, which could cause inadvertent
	// sharing (and race connditions) between concurrent calls
	if len(o1) == 0 {
		return o2
	} else if len(o2) == 0 {
		return o1
	}
	ret := make([]CallOption, len(o1)+len(o2))
	copy(ret, o1)
	copy(ret[len(o1):], o2)
	return ret
}

var unaryStreamDesc = &StreamDesc{ServerStreams: false, ClientStreams: false}
