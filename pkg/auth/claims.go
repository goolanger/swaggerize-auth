package auth

import "context"

type Claims struct {
	// id
	ID string `json:"id,omitempty"`

	// scopes
	Scopes string `json:"scopes,omitempty"`
}

func (a *Auth) Decode(token string) (*Claims, error) {
	if ti, err := a.server.Manager.LoadAccessToken(context.TODO(), token); err != nil {
		return nil, err
	} else {
		return &Claims{
			ID:     ti.GetUserID(),
			Scopes: ti.GetScope(),
		}, nil
	}
}
