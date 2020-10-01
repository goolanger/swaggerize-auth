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
	"github.com/go-openapi/validate"
)

// NewStateSubmitParams creates a new StateSubmitParams object
// no default values defined in spec.
func NewStateSubmitParams() StateSubmitParams {

	return StateSubmitParams{}
}

// StateSubmitParams contains all the bound params for the state submit operation
// typically these are obtained from a http.Request
//
// swagger:parameters StateSubmit
type StateSubmitParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  Required: true
	  In: query
	*/
	Action string
	/*
	  Required: true
	  In: formData
	*/
	Email string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewStateSubmitParams() beforehand.
func (o *StateSubmitParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	qs := runtime.Values(r.URL.Query())

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err != http.ErrNotMultipart {
			return errors.New(400, "%v", err)
		} else if err := r.ParseForm(); err != nil {
			return errors.New(400, "%v", err)
		}
	}
	fds := runtime.Values(r.Form)

	qAction, qhkAction, _ := qs.GetOK("action")
	if err := o.bindAction(qAction, qhkAction, route.Formats); err != nil {
		res = append(res, err)
	}

	fdEmail, fdhkEmail, _ := fds.GetOK("email")
	if err := o.bindEmail(fdEmail, fdhkEmail, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindAction binds and validates parameter Action from query.
func (o *StateSubmitParams) bindAction(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("action", "query", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true
	// AllowEmptyValue: false
	if err := validate.RequiredString("action", "query", raw); err != nil {
		return err
	}

	o.Action = raw

	if err := o.validateAction(formats); err != nil {
		return err
	}

	return nil
}

// validateAction carries on validations for parameter Action
func (o *StateSubmitParams) validateAction(formats strfmt.Registry) error {

	if err := validate.EnumCase("action", "query", o.Action, []interface{}{"activation", "recovery"}, true); err != nil {
		return err
	}

	return nil
}

// bindEmail binds and validates parameter Email from formData.
func (o *StateSubmitParams) bindEmail(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("email", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("email", "formData", raw); err != nil {
		return err
	}

	o.Email = raw

	return nil
}
