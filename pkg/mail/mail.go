package mail

import "github.com/go-openapi/strfmt"

type Mailer interface {
	SendMail(*Mail) error
	Init() error
}

type Mail struct {
	// from
	From string

	// to
	To []string

	// subject
	Subject string

	// body
	Body []byte

	// attachments
	Attachments []strfmt.Base64

	//	attempts
	attempts int
}
