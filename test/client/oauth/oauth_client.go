// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

import (
	"fmt"

	"github.com/go-openapi/runtime"
	"github.com/go-openapi/strfmt"
)

// New creates a new oauth API client.
func New(transport runtime.ClientTransport, formats strfmt.Registry) ClientService {
	return &Client{transport: transport, formats: formats}
}

/*
Client for oauth API
*/
type Client struct {
	transport runtime.ClientTransport
	formats   strfmt.Registry
}

// ClientService is the interface for Client methods
type ClientService interface {
	Authorize(params *AuthorizeParams) (*AuthorizeOK, error)

	AuthorizeSubmit(params *AuthorizeSubmitParams) (*AuthorizeSubmitOK, error)

	Provider(params *ProviderParams) error

	Token(params *TokenParams) (*TokenOK, error)

	SetTransport(transport runtime.ClientTransport)
}

/*
  Authorize authorize API
*/
func (a *Client) Authorize(params *AuthorizeParams) (*AuthorizeOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAuthorizeParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "Authorize",
		Method:             "GET",
		PathPattern:        "/auth/oauth/authorize",
		ProducesMediaTypes: []string{"text/html"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &AuthorizeReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*AuthorizeOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for Authorize: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  AuthorizeSubmit authorize submit API
*/
func (a *Client) AuthorizeSubmit(params *AuthorizeSubmitParams) (*AuthorizeSubmitOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewAuthorizeSubmitParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "AuthorizeSubmit",
		Method:             "POST",
		PathPattern:        "/auth/oauth/authorize",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &AuthorizeSubmitReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*AuthorizeSubmitOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for AuthorizeSubmit: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

/*
  Provider provider API
*/
func (a *Client) Provider(params *ProviderParams) error {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewProviderParams()
	}

	_, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "Provider",
		Method:             "GET",
		PathPattern:        "/auth/oauth/providers/{provider}",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/json"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &ProviderReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return err
	}
	return nil
}

/*
  Token token API
*/
func (a *Client) Token(params *TokenParams) (*TokenOK, error) {
	// TODO: Validate the params before sending
	if params == nil {
		params = NewTokenParams()
	}

	result, err := a.transport.Submit(&runtime.ClientOperation{
		ID:                 "Token",
		Method:             "POST",
		PathPattern:        "/auth/oauth/token",
		ProducesMediaTypes: []string{"application/json"},
		ConsumesMediaTypes: []string{"application/x-www-form-urlencoded"},
		Schemes:            []string{"http", "https"},
		Params:             params,
		Reader:             &TokenReader{formats: a.formats},
		Context:            params.Context,
		Client:             params.HTTPClient,
	})
	if err != nil {
		return nil, err
	}
	success, ok := result.(*TokenOK)
	if ok {
		return success, nil
	}
	// unexpected success response
	// safeguard: normally, absent a default response, unknown success responses return an error above: so this is a codegen issue
	msg := fmt.Sprintf("unexpected success response for Token: API contract not enforced by server. Client expected to get an error, but got: %T", result)
	panic(msg)
}

// SetTransport changes the transport on the client
func (a *Client) SetTransport(transport runtime.ClientTransport) {
	a.transport = transport
}
