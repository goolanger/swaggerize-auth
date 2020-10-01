package db

import (
	"errors"
	"fmt"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"strconv"
	"strings"
)

type Default struct {
	Host       string `yaml:"host,omitempty"`
	Port       int    `yaml:"port,omitempty"`
	Ssl        string `yaml:"sslmode,omitempty" values:"require, verify-full, verify-ca, disable"`
	Name       string `yaml:"name,omitempty"`
	User       string `yaml:"username,omitempty"`
	Pass       string `yaml:"password,omitempty"`
	Handler    string `yaml:"handler,omitempty" values:"postgres, sqlite"`
	connection *gorm.DB
}

func (c *Default) Execute() *gorm.DB {
	return c.connection
}

func (c *Default) Init() error {
	switch c.Handler {
	case "postgres":
		return c.Postgres()
	case "sqlite":
		return c.SQLite()
	default:
		return errors.New("unknown handler: " + c.Handler)
	}
}

func (c *Default) Postgres() error {
	var err error

	if err = c.validateConnection("postgres"); err != nil {
		return err
	}

	var conf []string

	if c.Host != "" {
		conf = append(conf, "host="+c.Host)
	}
	if c.Port > 0 {
		conf = append(conf, "port="+strconv.Itoa(c.Port))
	}
	if c.Name != "" {
		conf = append(conf, "dbname="+c.Name)
	}
	if c.User != "" {
		conf = append(conf, "user="+c.User)
	}
	if c.Pass != "" {
		conf = append(conf, "password="+c.Pass)
	}
	if c.Ssl == "require" || c.Ssl == "verify-full" || c.Ssl == "verify-ca" || c.Ssl == "disable" {
		conf = append(conf, "sslmode="+c.Ssl)
	}

	dsn := strings.Join(conf, " ")

	if c.connection, err = gorm.Open(postgres.Open(dsn), &gorm.Config{}); err != nil {
		return err
	}

	return nil
}

func (c *Default) SQLite() error {
	var err error

	if err = c.validateConnection("sqlite"); err != nil {
		return err
	}

	if c.connection, err = gorm.Open(sqlite.Open(c.Name), &gorm.Config{}); err != nil {
		return err
	}

	return nil
}

func (c *Default) validateConnection(driver string) error {
	if c.Handler != driver {
		return fmt.Errorf("pkg was initialized as: %s instead of: %s", c.Handler, driver)
	}
	return nil
}
