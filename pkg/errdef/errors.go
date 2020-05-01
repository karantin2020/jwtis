package errdef

import (
	"context"
	"fmt"
	"io"
	"strings"

	errors "github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	// ==== Basic errors ==== //

	// ErrInternal error, followed by codes.Internal
	ErrInternal = errors.New("internal error")
	// ErrInvalidArgument error, followed by codes.InvalidArgument
	ErrInvalidArgument = errors.New("invalid request argument error")
	// ErrDecodeGRPCRequest error
	ErrDecodeGRPCRequest = errors.Wrap(ErrInternal, "decode GRPC request error")
	// ErrEncodeGRPCResponse error
	ErrEncodeGRPCResponse = errors.Wrap(ErrInternal, "encode GRPC response error")
	// ErrNotExpectedGRPCRequestType error
	ErrNotExpectedGRPCRequestType = errors.Wrap(ErrInvalidArgument, "not expected grpc request type")
	// ErrNotExpectedGRPCResponseType error
	ErrNotExpectedGRPCResponseType = errors.Wrap(ErrInternal, "not expected grpc response type")
	// ErrNotExpectedProtoGRPCResponseType error
	ErrNotExpectedProtoGRPCResponseType = errors.Wrap(ErrInternal, "not expected proto grpc response type")

	// ==== Operational errors ==== //

	// ErrUnmarshalRequest error
	ErrUnmarshalRequest = errors.Wrap(ErrInvalidArgument, "error unmarshal request")
	// ErrMarshalRequest error
	ErrMarshalRequest = errors.Wrap(ErrInternal, "error marshal request")
	// ErrUnmarshalResponse error
	ErrUnmarshalResponse = errors.Wrap(ErrInternal, "error unmarshal response")
	// ErrMarshalResponse error
	ErrMarshalResponse = errors.Wrap(ErrInternal, "error marshal response")
	// ErrMarshalResponseKey error
	ErrMarshalResponseKey = errors.Wrap(ErrInternal, "marshal response key error")
	// ErrUnimplemented error
	ErrUnimplemented = errors.Wrap(ErrInternal, "unimplemented method")
	// ErrInvalidKID error
	ErrInvalidKID = errors.Wrap(ErrInvalidArgument, "invalid KID")
	// ErrInvalidClaims error
	ErrInvalidClaims = errors.Wrap(ErrInvalidArgument, "invalid Claims")
	// ErrKIDNotExists error
	ErrKIDNotExists = errors.Wrap(ErrInvalidArgument, "enc, sig keys are not found for requested kid")
	// ErrDecryptRefreshToken error
	ErrDecryptRefreshToken = errors.Wrap(ErrInvalidArgument, "refresh token couldn't be decrypted")
	// ErrInvalidRefreshToken error
	ErrInvalidRefreshToken = errors.Wrap(ErrInvalidArgument, "invalid refresh token")
	// ErrRefreshTokenExpired error
	ErrRefreshTokenExpired = errors.Wrap(ErrInvalidRefreshToken, "refresh token expired")
	// ErrInvalidRefreshClaims error
	ErrInvalidRefreshClaims = errors.Wrap(ErrInvalidRefreshToken, "invalid refresh token claims")
	// ErrNullKeysRepo error
	ErrNullKeysRepo = errors.Wrap(ErrInternal, "keys repository pointer is null")
)

// Error func
func Error(c codes.Code, msg string) error {
	if c == codes.OK {
		return nil
	}
	err := errors.New(msg)
	st := statusFromErr(c, err, false)
	return st.Err()
}

// Errorf func
func Errorf(c codes.Code, msg string, a ...interface{}) error {
	if c == codes.OK {
		return nil
	}
	err := errors.Errorf(msg, a...)
	st := statusFromErr(c, err, false)
	return st.Err()
}

// WrapErr func
func WrapErr(err error, c codes.Code, msg string) error {
	if c == codes.OK {
		return nil
	}
	if err == nil {
		return nil
	}
	err = errors.Wrap(err, msg)
	st := statusFromErr(c, err, false)
	return st.Err()
}

// WrapErrf func
func WrapErrf(err error, c codes.Code, msg string, a ...interface{}) error {
	if c == codes.OK {
		return nil
	}
	if err == nil {
		return nil
	}
	err = errors.Wrapf(err, msg, a...)
	st := statusFromErr(c, err, false)
	return st.Err()
}

// Code func
func Code(err error) codes.Code {
	st, ok := status.FromError(err)
	if ok {
		return st.Code()
	}
	return codes.Unknown
}

func statusFromErr(c codes.Code, err error, withStack bool) *status.Status {
	st := status.Convert(err)
	stProto := st.Proto()
	stProto.Code = int32(c)
	if withStack {
		stProto.Message = fmt.Sprintf("%+v", err)
	}
	st = status.FromProto(stProto)
	return st
}

func toStatusError(c codes.Code, err error) error {
	return statusFromErr(c, err, false).Err()
}

func convertToStatusError(err error) error {
	var c codes.Code
	if Is(err, ErrInternal) {
		c = codes.Internal
	} else if Is(err, ErrInvalidArgument) {
		c = codes.InvalidArgument
	} else {
		c = codes.Unknown
	}
	return toStatusError(c, err)
}

// toRPCErr converts an error into an error from the status package.
func toRPCErr(err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if err == io.ErrUnexpectedEOF {
		return status.Error(codes.Internal, err.Error())
	}
	if _, ok := status.FromError(err); ok {
		return err
	}

	var c codes.Code

	switch err {
	case context.DeadlineExceeded:
		c = codes.DeadlineExceeded
	case context.Canceled:
		c = codes.Canceled
	default:
		if Is(err, ErrInternal) {
			c = codes.Internal
		} else if Is(err, ErrInvalidArgument) {
			c = codes.InvalidArgument
		} else {
			c = codes.Unknown
		}
	}

	return status.Error(c, err.Error())
}

// Is func
func Is(err, target error) bool {
	if ok := errors.Is(err, target); ok {
		return ok
	}
	stErr, okErr := status.FromError(err)
	stTarget, okTarget := status.FromError(err)
	if stErr.Code() != stTarget.Code() {
		return false
	}
	return okErr && okTarget && strings.Contains(stErr.Message(), stTarget.Message())
}

// UnaryServerErrorInterceptor returns a new unary server interceptor for error handling
func UnaryServerErrorInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		resp, err := handler(ctx, req)
		return resp, toRPCErr(err)
	}
}

// StreamServerInterceptor returns a new streaming server interceptor for panic recovery.
func StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv interface{}, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		fmt.Printf("StreamServerInterceptor")
		err = handler(srv, stream)
		return toRPCErr(err)
	}
}
