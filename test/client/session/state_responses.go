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

// StateReader is a Reader for the State structure.
type StateReader struct {
	formats strfmt.Registry
}

// ReadResponse reads a server response into the received o.
func (o *StateReader) ReadResponse(response runtime.ClientResponse, consumer runtime.Consumer) (interface{}, error) {
	switch response.Code() {
	case 200:
		result := NewStateOK()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return result, nil
	case 500:
		result := NewStateInternalServerError()
		if err := result.readResponse(response, consumer, o.formats); err != nil {
			return nil, err
		}
		return nil, result

	default:
		return nil, runtime.NewAPIError("unknown error", response, response.Code())
	}
}

// NewStateOK creates a StateOK with default headers values
func NewStateOK() *StateOK {
	return &StateOK{}
}

/*StateOK handles this case with default header values.

OK
*/
type StateOK struct {
}

func (o *StateOK) Error() string {
	return fmt.Sprintf("[GET /api/session/state][%d] stateOK ", 200)
}

func (o *StateOK) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	return nil
}

// NewStateInternalServerError creates a StateInternalServerError with default headers values
func NewStateInternalServerError() *StateInternalServerError {
	return &StateInternalServerError{}
}

/*StateInternalServerError handles this case with default header values.

internal server error
*/
type StateInternalServerError struct {
	Payload string
}

func (o *StateInternalServerError) Error() string {
	return fmt.Sprintf("[GET /api/session/state][%d] stateInternalServerError  %+v", 500, o.Payload)
}

func (o *StateInternalServerError) GetPayload() string {
	return o.Payload
}

func (o *StateInternalServerError) readResponse(response runtime.ClientResponse, consumer runtime.Consumer, formats strfmt.Registry) error {

	// response payload
	if err := consumer.Consume(response.Body(), &o.Payload); err != nil && err != io.EOF {
		return err
	}

	return nil
}