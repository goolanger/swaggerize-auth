package mail

import (
	"fmt"
	"net/smtp"
	"time"
)

type Default struct {
	User        string        `yaml:"username"`
	Password    string        `yaml:"password"`
	SMTPAddress string        `yaml:"smtpaddress"`
	SMTPPort    int           `yaml:"smtpport"`
	Wait        time.Duration `yaml:"wait"`
	Attempts    int           `yaml:"attempts"`
	incoming    chan *Mail
}

func (c *Default) Init() (err error) {
	c.incoming = make(chan *Mail, 10)
	go c.run()
	return
}

func (c *Default) SendMail(m *Mail) (err error) {
	c.incoming <- m
	return
}

func (c *Default) sendMail(m *Mail) {
	SMTPServer := fmt.Sprintf("%s:%d", c.SMTPAddress, c.SMTPPort)

	mime := "MIME-version: 1.0;\nContent-Type: text/html; charset=utf-8;\n\n"
	subject := "Subject: " + m.Subject + "!\n"

	msg := []byte(subject + mime + "\n")
	msg = append(msg, m.Body...)

	err := smtp.SendMail(SMTPServer, smtp.PlainAuth("", c.User, c.Password, c.SMTPAddress), m.From, m.To, msg)

	if err != nil {
		time.Sleep(c.Wait)
		m.attempts++
		c.incoming <- m
	}
}

func (c *Default) run() {
	for m := range c.incoming {
		if m.attempts < c.Attempts {
			go c.sendMail(m)
		}
	}
}
