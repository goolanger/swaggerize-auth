// Code generated by go-swagger; DO NOT EDIT.

package session

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// StateHandlerFunc turns a function with the right signature into a state handler
type StateHandlerFunc func(StateParams) middleware.Responder

// Handle executing the request and returning a response
func (fn StateHandlerFunc) Handle(params StateParams) middleware.Responder {
	return fn(params)
}

// StateHandler interface for that can handle valid state params
type StateHandler interface {
	Handle(StateParams) middleware.Responder
}

// NewState creates a new http.Handler for the state operation
func NewState(ctx *middleware.Context, handler StateHandler) *State {
	return &State{Context: ctx, Handler: handler}
}

/*State swagger:route GET /api/session/state Session state

State state API

*/
type State struct {
	Context *middleware.Context
	Handler StateHandler
}

func (o *State) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		r = rCtx
	}
	var Params = NewStateParams()

	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request

	o.Context.Respond(rw, r, route.Produces, route, res)

}
