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

// NewStateSubmitParams creates a new StateSubmitParams object
// with the default values initialized.
func NewStateSubmitParams() *StateSubmitParams {
	var ()
	return &StateSubmitParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewStateSubmitParamsWithTimeout creates a new StateSubmitParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewStateSubmitParamsWithTimeout(timeout time.Duration) *StateSubmitParams {
	var ()
	return &StateSubmitParams{

		timeout: timeout,
	}
}

// NewStateSubmitParamsWithContext creates a new StateSubmitParams object
// with the default values initialized, and the ability to set a context for a request
func NewStateSubmitParamsWithContext(ctx context.Context) *StateSubmitParams {
	var ()
	return &StateSubmitParams{

		Context: ctx,
	}
}

// NewStateSubmitParamsWithHTTPClient creates a new StateSubmitParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewStateSubmitParamsWithHTTPClient(client *http.Client) *StateSubmitParams {
	var ()
	return &StateSubmitParams{
		HTTPClient: client,
	}
}

/*StateSubmitParams contains all the parameters to send to the API endpoint
for the state submit operation typically these are written to a http.Request
*/
type StateSubmitParams struct {

	/*Action*/
	Action string
	/*Email*/
	Email string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the state submit params
func (o *StateSubmitParams) WithTimeout(timeout time.Duration) *StateSubmitParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the state submit params
func (o *StateSubmitParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the state submit params
func (o *StateSubmitParams) WithContext(ctx context.Context) *StateSubmitParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the state submit params
func (o *StateSubmitParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the state submit params
func (o *StateSubmitParams) WithHTTPClient(client *http.Client) *StateSubmitParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the state submit params
func (o *StateSubmitParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithAction adds the action to the state submit params
func (o *StateSubmitParams) WithAction(action string) *StateSubmitParams {
	o.SetAction(action)
	return o
}

// SetAction adds the action to the state submit params
func (o *StateSubmitParams) SetAction(action string) {
	o.Action = action
}

// WithEmail adds the email to the state submit params
func (o *StateSubmitParams) WithEmail(email string) *StateSubmitParams {
	o.SetEmail(email)
	return o
}

// SetEmail adds the email to the state submit params
func (o *StateSubmitParams) SetEmail(email string) {
	o.Email = email
}

// WriteToRequest writes these params to a swagger request
func (o *StateSubmitParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param action
	qrAction := o.Action
	qAction := qrAction
	if qAction != "" {
		if err := r.SetQueryParam("action", qAction); err != nil {
			return err
		}
	}

	// form param email
	frEmail := o.Email
	fEmail := frEmail
	if fEmail != "" {
		if err := r.SetFormParam("email", fEmail); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}