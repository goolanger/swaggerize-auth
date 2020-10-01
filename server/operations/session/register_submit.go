// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// RegisterSubmitHandlerFunc turns a function with the right signature into a register submit handler
type RegisterSubmitHandlerFunc func(RegisterSubmitParams) middleware.Responder

// Handle executing the request and returning a response
func (fn RegisterSubmitHandlerFunc) Handle(params RegisterSubmitParams) middleware.Responder {
	return fn(params)
}

// RegisterSubmitHandler interface for that can handle valid register submit params
type RegisterSubmitHandler interface {
	Handle(RegisterSubmitParams) middleware.Responder
}

// NewRegisterSubmit creates a new http.Handler for the register submit operation
func NewRegisterSubmit(ctx *middleware.Context, handler RegisterSubmitHandler) *RegisterSubmit {
	return &RegisterSubmit{Context: ctx, Handler: handler}
}

/*RegisterSubmit swagger:route POST /api/session/register Session registerSubmit

RegisterSubmit register submit API

*/
type RegisterSubmit struct {
	Context *middleware.Context
	Handler RegisterSubmitHandler
}

func (o *RegisterSubmit) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewRegisterSubmitParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
