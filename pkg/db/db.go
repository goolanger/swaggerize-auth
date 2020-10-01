package db

import "gorm.io/gorm"

type Connection interface {
	Execute() *gorm.DB
	Connect() error
}
