package control

import (
	"errors"
	"fmt"
)

// Error is a stable protocol-facing operation error. Cause is retained for
// daemon diagnostics but is never serialized by the HTTP handler.
type Error struct {
	Status  int
	Code    string
	Message string
	Cause   error
}

func NewError(status int, code, message string, cause error) *Error {
	return &Error{Status: status, Code: code, Message: message, Cause: cause}
}

func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Code, e.Cause)
	}
	return e.Code
}

func (e *Error) Unwrap() error { return e.Cause }

func asError(err error) (*Error, bool) {
	var opErr *Error
	ok := errors.As(err, &opErr)
	return opErr, ok
}
