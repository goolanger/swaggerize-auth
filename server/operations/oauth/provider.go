// Code generated by go-swagger; DO NOT EDIT.

package oauth

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// ProviderHandlerFunc turns a function with the right signature into a provider handler
type ProviderHandlerFunc func(ProviderParams) middleware.Responder

// Handle executing the request and returning a response
func (fn ProviderHandlerFunc) Handle(params ProviderParams) middleware.Responder {
	return fn(params)
}

// ProviderHandler interface for that can handle valid provider params
type ProviderHandler interface {
	Handle(ProviderParams) middleware.Responder
}

// NewProvider creates a new http.Handler for the provider operation
func NewProvider(ctx *middleware.Context, handler ProviderHandler) *Provider {
	return &Provider{Context: ctx, Handler: handler}
}

/*Provider swagger:route GET /api/oauth/providers/{provider} Oauth provider

Provider provider API

*/
type Provider struct {
	Context *middleware.Context
	Handler ProviderHandler
}

func (o *Provider) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewProviderParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
