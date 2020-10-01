package auth

import (
	"github.com/goolanger/swaggerize-auth/pkg/db"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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

	// password
	Password string `json:"digest,omitempty"`
}

func (u *User) BeforeUpdate(_ *gorm.DB) error {
	return u.setDigest()
}

func (u *User) BeforeCreate(_ *gorm.DB) error {
	return u.setDigest()
}

func (u *User) setDigest() error {
	if u.Password == "" {
		return nil
	}

	if pass, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost); err != nil {
		return err
	} else {
		u.Password = string(pass)
		return nil
	}
}

func GetUserByEmail(connection db.Connection, email string) (*User, error) {
	var user User
	if err := connection.Execute().First(&user, "email = ?", email).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func GetUserById(connection db.Connection, id int64) (*User, error) {
	var user User
	if err := connection.Execute().First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func CreateUser(connection db.Connection, email, password string, active, verified bool) (*User, error) {
	user := User{
		Email:    email,
		Active:   active,
		Verified: verified,
		Password: password,
	}

	if err := connection.Execute().Create(&user).Error; err != nil {
		return nil, err
	}

	return &user, nil
}

func UpdateUser(connection db.Connection, userId int64, user *User) error {
	if err := connection.Execute().First(&User{}, userId).Updates(user).Error; err != nil {
		return err
	}
	return nil
}
