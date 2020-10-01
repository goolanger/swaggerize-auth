// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// StateSubmitHandlerFunc turns a function with the right signature into a state submit handler
type StateSubmitHandlerFunc func(StateSubmitParams) middleware.Responder

// Handle executing the request and returning a response
func (fn StateSubmitHandlerFunc) Handle(params StateSubmitParams) middleware.Responder {
	return fn(params)
}

// StateSubmitHandler interface for that can handle valid state submit params
type StateSubmitHandler interface {
	Handle(StateSubmitParams) middleware.Responder
}

// NewStateSubmit creates a new http.Handler for the state submit operation
func NewStateSubmit(ctx *middleware.Context, handler StateSubmitHandler) *StateSubmit {
	return &StateSubmit{Context: ctx, Handler: handler}
}

/*StateSubmit swagger:route POST /auth/session/state Session stateSubmit

StateSubmit state submit API

*/
type StateSubmit struct {
	Context *middleware.Context
	Handler StateSubmitHandler
}

func (o *StateSubmit) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewStateSubmitParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
