// Code generated by go-swagger; DO NOT EDIT.

package oauth

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

// NewAuthorizeSubmitParams creates a new AuthorizeSubmitParams object
// no default values defined in spec.
func NewAuthorizeSubmitParams() AuthorizeSubmitParams {

	return AuthorizeSubmitParams{}
}

// AuthorizeSubmitParams contains all the bound params for the authorize submit operation
// typically these are obtained from a http.Request
//
// swagger:parameters AuthorizeSubmit
type AuthorizeSubmitParams struct {

	// HTTP Request Object
	HTTPRequest *http.Request `json:"-"`

	/*
	  Required: true
	  In: formData
	*/
	ClientID string
	/*
	  Required: true
	  In: formData
	*/
	Password string
	/*
	  Required: true
	  In: formData
	*/
	RedirectURI string
	/*
	  Required: true
	  In: formData
	*/
	ResponseType string
	/*
	  Required: true
	  In: formData
	*/
	Scope string
	/*
	  Required: true
	  In: formData
	*/
	State string
	/*
	  Required: true
	  In: formData
	*/
	Username string
}

// BindRequest both binds and validates a request, it assumes that complex things implement a Validatable(strfmt.Registry) error interface
// for simple values it will use straight method calls.
//
// To ensure default values, the struct must have been initialized with NewAuthorizeSubmitParams() beforehand.
func (o *AuthorizeSubmitParams) BindRequest(r *http.Request, route *middleware.MatchedRoute) error {
	var res []error

	o.HTTPRequest = r

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		if err != http.ErrNotMultipart {
			return errors.New(400, "%v", err)
		} else if err := r.ParseForm(); err != nil {
			return errors.New(400, "%v", err)
		}
	}
	fds := runtime.Values(r.Form)

	fdClientID, fdhkClientID, _ := fds.GetOK("client_id")
	if err := o.bindClientID(fdClientID, fdhkClientID, route.Formats); err != nil {
		res = append(res, err)
	}

	fdPassword, fdhkPassword, _ := fds.GetOK("password")
	if err := o.bindPassword(fdPassword, fdhkPassword, route.Formats); err != nil {
		res = append(res, err)
	}

	fdRedirectURI, fdhkRedirectURI, _ := fds.GetOK("redirect_uri")
	if err := o.bindRedirectURI(fdRedirectURI, fdhkRedirectURI, route.Formats); err != nil {
		res = append(res, err)
	}

	fdResponseType, fdhkResponseType, _ := fds.GetOK("response_type")
	if err := o.bindResponseType(fdResponseType, fdhkResponseType, route.Formats); err != nil {
		res = append(res, err)
	}

	fdScope, fdhkScope, _ := fds.GetOK("scope")
	if err := o.bindScope(fdScope, fdhkScope, route.Formats); err != nil {
		res = append(res, err)
	}

	fdState, fdhkState, _ := fds.GetOK("state")
	if err := o.bindState(fdState, fdhkState, route.Formats); err != nil {
		res = append(res, err)
	}

	fdUsername, fdhkUsername, _ := fds.GetOK("username")
	if err := o.bindUsername(fdUsername, fdhkUsername, route.Formats); err != nil {
		res = append(res, err)
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}

// bindClientID binds and validates parameter ClientID from formData.
func (o *AuthorizeSubmitParams) bindClientID(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("client_id", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("client_id", "formData", raw); err != nil {
		return err
	}

	o.ClientID = raw

	return nil
}

// bindPassword binds and validates parameter Password from formData.
func (o *AuthorizeSubmitParams) bindPassword(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("password", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("password", "formData", raw); err != nil {
		return err
	}

	o.Password = raw

	return nil
}

// bindRedirectURI binds and validates parameter RedirectURI from formData.
func (o *AuthorizeSubmitParams) bindRedirectURI(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("redirect_uri", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("redirect_uri", "formData", raw); err != nil {
		return err
	}

	o.RedirectURI = raw

	return nil
}

// bindResponseType binds and validates parameter ResponseType from formData.
func (o *AuthorizeSubmitParams) bindResponseType(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("response_type", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("response_type", "formData", raw); err != nil {
		return err
	}

	o.ResponseType = raw

	if err := o.validateResponseType(formats); err != nil {
		return err
	}

	return nil
}

// validateResponseType carries on validations for parameter ResponseType
func (o *AuthorizeSubmitParams) validateResponseType(formats strfmt.Registry) error {

	if err := validate.EnumCase("response_type", "formData", o.ResponseType, []interface{}{"code", "token"}, true); err != nil {
		return err
	}

	return nil
}

// bindScope binds and validates parameter Scope from formData.
func (o *AuthorizeSubmitParams) bindScope(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("scope", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("scope", "formData", raw); err != nil {
		return err
	}

	o.Scope = raw

	return nil
}

// bindState binds and validates parameter State from formData.
func (o *AuthorizeSubmitParams) bindState(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("state", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("state", "formData", raw); err != nil {
		return err
	}

	o.State = raw

	return nil
}

// bindUsername binds and validates parameter Username from formData.
func (o *AuthorizeSubmitParams) bindUsername(rawData []string, hasKey bool, formats strfmt.Registry) error {
	if !hasKey {
		return errors.Required("username", "formData", rawData)
	}
	var raw string
	if len(rawData) > 0 {
		raw = rawData[len(rawData)-1]
	}

	// Required: true

	if err := validate.RequiredString("username", "formData", raw); err != nil {
		return err
	}

	o.Username = raw

	return nil
}
