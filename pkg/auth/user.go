package auth

import (
	"golang.org/x/crypto/bcrypt"
)

type User struct {
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

func (a *Auth) GetUserByEmail(email string) (*User, error) {
	var user User
	if err := a.connection.Execute().First(&user, "email = ?", email).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *Auth) GetUserById(id int64) (*User, error) {
	var user User
	if err := a.connection.Execute().First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (a *Auth) CreateUser(email, password string, active, verified bool) (user *User, err error) {
	if password, err = a.GetDigest(password); err != nil {
		return
	}

	user = &User{
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
