// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// RegisterActivateHandlerFunc turns a function with the right signature into a register activate handler
type RegisterActivateHandlerFunc func(RegisterActivateParams) middleware.Responder

// Handle executing the request and returning a response
func (fn RegisterActivateHandlerFunc) Handle(params RegisterActivateParams) middleware.Responder {
	return fn(params)
}

// RegisterActivateHandler interface for that can handle valid register activate params
type RegisterActivateHandler interface {
	Handle(RegisterActivateParams) middleware.Responder
}

// NewRegisterActivate creates a new http.Handler for the register activate operation
func NewRegisterActivate(ctx *middleware.Context, handler RegisterActivateHandler) *RegisterActivate {
	return &RegisterActivate{Context: ctx, Handler: handler}
}

/*RegisterActivate swagger:route GET /api/session/register/activate Session registerActivate

RegisterActivate register activate API

*/
type RegisterActivate struct {
	Context *middleware.Context
	Handler RegisterActivateHandler
}

func (o *RegisterActivate) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewRegisterActivateParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
