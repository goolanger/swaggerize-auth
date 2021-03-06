// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"context"
	"net/http"
	"time"

	"github.com/go-openapi/errors"
	"github.com/go-openapi/runtime"
	cr "github.com/go-openapi/runtime/client"
	"github.com/go-openapi/strfmt"
)

// NewRegisterSubmitParams creates a new RegisterSubmitParams object
// with the default values initialized.
func NewRegisterSubmitParams() *RegisterSubmitParams {
	var ()
	return &RegisterSubmitParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewRegisterSubmitParamsWithTimeout creates a new RegisterSubmitParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewRegisterSubmitParamsWithTimeout(timeout time.Duration) *RegisterSubmitParams {
	var ()
	return &RegisterSubmitParams{

		timeout: timeout,
	}
}

// NewRegisterSubmitParamsWithContext creates a new RegisterSubmitParams object
// with the default values initialized, and the ability to set a context for a request
func NewRegisterSubmitParamsWithContext(ctx context.Context) *RegisterSubmitParams {
	var ()
	return &RegisterSubmitParams{

		Context: ctx,
	}
}

// NewRegisterSubmitParamsWithHTTPClient creates a new RegisterSubmitParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewRegisterSubmitParamsWithHTTPClient(client *http.Client) *RegisterSubmitParams {
	var ()
	return &RegisterSubmitParams{
		HTTPClient: client,
	}
}

/*RegisterSubmitParams contains all the parameters to send to the API endpoint
for the register submit operation typically these are written to a http.Request
*/
type RegisterSubmitParams struct {

	/*Email*/
	Email string
	/*Password*/
	Password string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the register submit params
func (o *RegisterSubmitParams) WithTimeout(timeout time.Duration) *RegisterSubmitParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the register submit params
func (o *RegisterSubmitParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the register submit params
func (o *RegisterSubmitParams) WithContext(ctx context.Context) *RegisterSubmitParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the register submit params
func (o *RegisterSubmitParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the register submit params
func (o *RegisterSubmitParams) WithHTTPClient(client *http.Client) *RegisterSubmitParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the register submit params
func (o *RegisterSubmitParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithEmail adds the email to the register submit params
func (o *RegisterSubmitParams) WithEmail(email string) *RegisterSubmitParams {
	o.SetEmail(email)
	return o
}

// SetEmail adds the email to the register submit params
func (o *RegisterSubmitParams) SetEmail(email string) {
	o.Email = email
}

// WithPassword adds the password to the register submit params
func (o *RegisterSubmitParams) WithPassword(password string) *RegisterSubmitParams {
	o.SetPassword(password)
	return o
}

// SetPassword adds the password to the register submit params
func (o *RegisterSubmitParams) SetPassword(password string) {
	o.Password = password
}

// WriteToRequest writes these params to a swagger request
func (o *RegisterSubmitParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// form param email
	frEmail := o.Email
	fEmail := frEmail
	if fEmail != "" {
		if err := r.SetFormParam("email", fEmail); err != nil {
			return err
		}
	}

	// form param password
	frPassword := o.Password
	fPassword := frPassword
	if fPassword != "" {
		if err := r.SetFormParam("password", fPassword); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
