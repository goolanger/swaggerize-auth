package auth

import (
	"golang.org/x/crypto/bcrypt"
)

type Identity struct {
	// id
	ID int64 `json:"id,omitempty" gorm:"primary_key"`

	// email
	Email string `json:"email,omitempty" gorm:"unique_index"`

	// active
	Active bool `json:"active,omitempty"`

	// verified
	Verified bool `json:"verified,omitempty"`

	// password digest
	Digest string `json:"digest,omitempty"`
}

func (a *Auth) GetDigest(password string) (digest string, err error) {
	data, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return
	}

	digest = string(data)
	return
}

func (a *Auth) GetIdentityByEmail(email string) (*Identity, error) {
	var user Identity
	if err := a.connection.Execute().First(&user, "email = ?", email).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *Auth) GetIdentityById(id int64) (*Identity, error) {
	var user Identity
	if err := a.connection.Execute().First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *Auth) CreateIdentity(email, password string, active, verified bool) (user *Identity, err error) {
	if password, err = a.GetDigest(password); err != nil {
		return
	}

	user = &Identity{
		Email:    email,
		Active:   active,
		Verified: verified,
		Digest:   password,
	}

	if err = a.connection.Execute().Create(user).Error; err != nil {
		return nil, err
	}

	return
}
