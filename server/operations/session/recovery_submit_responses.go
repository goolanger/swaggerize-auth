// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// RecoverySubmitOKCode is the HTTP code returned for type RecoverySubmitOK
const RecoverySubmitOKCode int = 200

/*RecoverySubmitOK OK

swagger:response recoverySubmitOK
*/
type RecoverySubmitOK struct {
}

// NewRecoverySubmitOK creates RecoverySubmitOK with default headers values
func NewRecoverySubmitOK() *RecoverySubmitOK {

	return &RecoverySubmitOK{}
}

// WriteResponse to the client
func (o *RecoverySubmitOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.Header().Del(runtime.HeaderContentType) //Remove Content-Type on empty responses

	rw.WriteHeader(200)
}

// RecoverySubmitInternalServerErrorCode is the HTTP code returned for type RecoverySubmitInternalServerError
const RecoverySubmitInternalServerErrorCode int = 500

/*RecoverySubmitInternalServerError internal server error

swagger:response recoverySubmitInternalServerError
*/
type RecoverySubmitInternalServerError struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewRecoverySubmitInternalServerError creates RecoverySubmitInternalServerError with default headers values
func NewRecoverySubmitInternalServerError() *RecoverySubmitInternalServerError {

	return &RecoverySubmitInternalServerError{}
}

// WithPayload adds the payload to the recovery submit internal server error response
func (o *RecoverySubmitInternalServerError) WithPayload(payload string) *RecoverySubmitInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the recovery submit internal server error response
func (o *RecoverySubmitInternalServerError) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *RecoverySubmitInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
