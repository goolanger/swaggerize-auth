// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"
	"io"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// RecoveryReader is a Reader for the Recovery structure.
type RecoveryReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *RecoveryReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewRecoveryOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewRecoveryInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewRecoveryOK creates a RecoveryOK with default headers values
func NewRecoveryOK() *RecoveryOK {
	return &RecoveryOK{}
}

/*RecoveryOK handles this case with default header values.

OK
*/
type RecoveryOK struct {
}

func (o *RecoveryOK) Error() string {
	return fmt.Sprintf("[GET /api/session/recovery][%d] recoveryOK ", 200)
}

func (o *RecoveryOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewRecoveryInternalServerError creates a RecoveryInternalServerError with default headers values
func NewRecoveryInternalServerError() *RecoveryInternalServerError {
	return &RecoveryInternalServerError{}
}

/*RecoveryInternalServerError handles this case with default header values.

internal server error
*/
type RecoveryInternalServerError struct {
	Payload string
}

func (o *RecoveryInternalServerError) Error() string {
	return fmt.Sprintf("[GET /api/session/recovery][%d] recoveryInternalServerError  %+v", 500, o.Payload)
}

func (o *RecoveryInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *RecoveryInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}
