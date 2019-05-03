package jwtispb

import (
	"fmt"

	"google.golang.org/grpc/codes"
)

type statusError Error

func (se *statusError) Error() string {
	p := (*Error)(se)
	return fmt.Sprintf("rpc error: code = %s desc = %s", codes.Code(p.Code), p.Message)
}

func (se *statusError) GRPCStatus() *Error {
	return (*Error)(se)
}

// Err returns Error as error interface
func (m *Error) Err() error {
	if codes.Code(m.Code) == codes.OK {
		return nil
	}
	return (*statusError)(m)
}

// WithDetails adds detail info to m *Error
func (m *Error) WithDetails(d string) *Error {
	m.Details = append(m.Details, d)
	return m
}

// FromError returns *Error from err
func FromError(err error) (*Error, bool) {
	if err == nil {
		return &Error{Code: int32(codes.OK)}, true
	}
	if se, ok := err.(interface {
		GRPCStatus() *Error
	}); ok {
		return se.GRPCStatus(), true
	}
	return &Error{Code: int32(codes.Unknown), Message: err.Error()}, false
}

// NewError returns new error
func NewError(c codes.Code, msg string, details ...string) error {
	err := &Error{Code: int32(c), Message: msg, Details: details}
	return (*statusError)(err)
}
