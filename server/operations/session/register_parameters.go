// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"net/http"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
)

// NewRegisterParams creates a new RegisterParams object
// no default values defined in spec.
func NewRegisterParams() RegisterParams {

	return RegisterParams{}
}

// RegisterParams contains all the bound params for the register operation
// typically these are obtained from a http.Request
//
// swagger:parameters Register
type RegisterParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  In: query
	*/
	LoginURL *string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewRegisterParams() beforehand.
func (o *RegisterParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	qLoginURL, qhkLoginURL, _ := qs.GetOK("login-url")
	if err := o.bindLoginURL(qLoginURL, qhkLoginURL, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindLoginURL binds and validates parameter LoginURL from query.
func (o *RegisterParams) bindLoginURL(rawData []string, hasKey bool, formats strfmt.Registry) error {
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: false
	// AllowEmptyValue: false
	if raw == "" { // empty values pass all other validations
		return nil
	}

	o.LoginURL = &raw

	return nil
}
