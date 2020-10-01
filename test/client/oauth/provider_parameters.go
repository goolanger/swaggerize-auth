// Code generated by go-swagger; DO NOT EDIT.

package oauth

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

// NewProviderParams creates a new ProviderParams object
// with the default values initialized.
func NewProviderParams() *ProviderParams {
	var ()
	return &ProviderParams{

		timeout: cr.DefaultTimeout,
	}
}

// NewProviderParamsWithTimeout creates a new ProviderParams object
// with the default values initialized, and the ability to set a timeout on a request
func NewProviderParamsWithTimeout(timeout time.Duration) *ProviderParams {
	var ()
	return &ProviderParams{

		timeout: timeout,
	}
}

// NewProviderParamsWithContext creates a new ProviderParams object
// with the default values initialized, and the ability to set a context for a request
func NewProviderParamsWithContext(ctx context.Context) *ProviderParams {
	var ()
	return &ProviderParams{

		Context: ctx,
	}
}

// NewProviderParamsWithHTTPClient creates a new ProviderParams object
// with the default values initialized, and the ability to set a custom HTTPClient for a request
func NewProviderParamsWithHTTPClient(client *http.Client) *ProviderParams {
	var ()
	return &ProviderParams{
		HTTPClient: client,
	}
}

/*ProviderParams contains all the parameters to send to the API endpoint
for the provider operation typically these are written to a http.Request
*/
type ProviderParams struct {

	/*Code*/
	Code string
	/*Provider*/
	Provider string
	/*State*/
	State string

	timeout    time.Duration
	Context    context.Context
	HTTPClient *http.Client
}

// WithTimeout adds the timeout to the provider params
func (o *ProviderParams) WithTimeout(timeout time.Duration) *ProviderParams {
	o.SetTimeout(timeout)
	return o
}

// SetTimeout adds the timeout to the provider params
func (o *ProviderParams) SetTimeout(timeout time.Duration) {
	o.timeout = timeout
}

// WithContext adds the context to the provider params
func (o *ProviderParams) WithContext(ctx context.Context) *ProviderParams {
	o.SetContext(ctx)
	return o
}

// SetContext adds the context to the provider params
func (o *ProviderParams) SetContext(ctx context.Context) {
	o.Context = ctx
}

// WithHTTPClient adds the HTTPClient to the provider params
func (o *ProviderParams) WithHTTPClient(client *http.Client) *ProviderParams {
	o.SetHTTPClient(client)
	return o
}

// SetHTTPClient adds the HTTPClient to the provider params
func (o *ProviderParams) SetHTTPClient(client *http.Client) {
	o.HTTPClient = client
}

// WithCode adds the code to the provider params
func (o *ProviderParams) WithCode(code string) *ProviderParams {
	o.SetCode(code)
	return o
}

// SetCode adds the code to the provider params
func (o *ProviderParams) SetCode(code string) {
	o.Code = code
}

// WithProvider adds the provider to the provider params
func (o *ProviderParams) WithProvider(provider string) *ProviderParams {
	o.SetProvider(provider)
	return o
}

// SetProvider adds the provider to the provider params
func (o *ProviderParams) SetProvider(provider string) {
	o.Provider = provider
}

// WithState adds the state to the provider params
func (o *ProviderParams) WithState(state string) *ProviderParams {
	o.SetState(state)
	return o
}

// SetState adds the state to the provider params
func (o *ProviderParams) SetState(state string) {
	o.State = state
}

// WriteToRequest writes these params to a swagger request
func (o *ProviderParams) WriteToRequest(r runtime.ClientRequest, reg strfmt.Registry) error {

	if err := r.SetTimeout(o.timeout); err != nil {
		return err
	}
	var res []error

	// query param code
	qrCode := o.Code
	qCode := qrCode
	if qCode != "" {
		if err := r.SetQueryParam("code", qCode); err != nil {
			return err
		}
	}

	// path param provider
	if err := r.SetPathParam("provider", o.Provider); err != nil {
		return err
	}

	// query param state
	qrState := o.State
	qState := qrState
	if qState != "" {
		if err := r.SetQueryParam("state", qState); err != nil {
			return err
		}
	}

	if len(res) > 0 {
		return errors.CompositeValidationError(res...)
	}
	return nil
}
