// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/runtime"
)

// TokenOKCode is the HTTP code returned for type TokenOK
const TokenOKCode int = 200

/*TokenOK operation success

swagger:response tokenOK
*/
type TokenOK struct {

	/*
	  In: Body
	*/
	Payload *TokenOKBody `json:"body,omitempty"`
}

// NewTokenOK creates TokenOK with default headers values
func NewTokenOK() *TokenOK {

	return &TokenOK{}
}

// WithPayload adds the payload to the token o k response
func (o *TokenOK) WithPayload(payload *TokenOKBody) *TokenOK {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the token o k response
func (o *TokenOK) SetPayload(payload *TokenOKBody) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *TokenOK) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(200)
	if o.Payload != nil {
		payload := o.Payload
		if err := producer.Produce(rw, payload); err != nil {
			panic(err) // let the recovery middleware deal with this
		}
	}
}

// TokenInternalServerErrorCode is the HTTP code returned for type TokenInternalServerError
const TokenInternalServerErrorCode int = 500

/*TokenInternalServerError internal server error

swagger:response tokenInternalServerError
*/
type TokenInternalServerError struct {

	/*
	  In: Body
	*/
	Payload string `json:"body,omitempty"`
}

// NewTokenInternalServerError creates TokenInternalServerError with default headers values
func NewTokenInternalServerError() *TokenInternalServerError {

	return &TokenInternalServerError{}
}

// WithPayload adds the payload to the token internal server error response
func (o *TokenInternalServerError) WithPayload(payload string) *TokenInternalServerError {
	o.Payload = payload
	return o
}

// SetPayload sets the payload to the token internal server error response
func (o *TokenInternalServerError) SetPayload(payload string) {
	o.Payload = payload
}

// WriteResponse to the client
func (o *TokenInternalServerError) WriteResponse(rw http.ResponseWriter, producer runtime.Producer) {

	rw.WriteHeader(500)
	payload := o.Payload
	if err := producer.Produce(rw, payload); err != nil {
		panic(err) // let the recovery middleware deal with this
	}
}
