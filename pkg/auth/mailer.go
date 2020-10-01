package auth

import (
	"bytes"
	template "github.com/arschles/go-bindata-html-template"
	"github.com/goolanger/swaggerize-auth/pkg/mail"
)

func (a *Auth) ActivateAccount(email string) error {
	files := []string{
		a.mailPage("/activation.tmpl"),
		a.mailPage("/base.tmpl"),
	}

	var user User
	if err := a.connection.Execute().First(&user, "email = ?", email).Error; err != nil {
		return err
	}

	token, err := a.GetActionToken(user.ID, Activation)
	if err != nil {
		return err
	}

	redirect := "https://localhost:20443/auth/session/register/activate?token=" + token

	return a.sendMail(email, "School - Account Activation", redirect, files...)
}

func (a *Auth) RecoverAccount(email string) error {
	files := []string{
		a.mailPage("/recovery.tmpl"),
		a.mailPage("/base.tmpl"),
	}

	var user User
	if err := a.connection.Execute().First(&user, "email = ?", email).Error; err != nil {
		return err
	}

	token, err := a.GetActionToken(user.ID, Recovery)
	if err != nil {
		return err
	}

	redirect := "https://localhost:20443/auth/session/recovery?token=" + token

	return a.sendMail(email, "School - Recovery Link", redirect, files...)
}

func (a *Auth) sendMail(target, subject, link string, files ...string) error {
	data := struct {
		Link string
	}{
		Link: link,
	}

	body, err := a.parseTemplate(data, files...)
	if err != nil {
		return err
	}

	return a.mailer.SendMail(&mail.Mail{
		From:    "noreply@host.com",
		To:      []string{target},
		Subject: subject,
		Body:    body,
	})
}

func (a *Auth) parseTemplate(data interface{}, files ...string) ([]byte, error) {
	ts, err := template.New("tmpl", a.assets).ParseFiles(files...)

	if err != nil {
		return nil, err
	}

	var tpl bytes.Buffer

	if err := ts.Execute(&tpl, data); err != nil {
		return nil, err
	}

	return tpl.Bytes(), nil
}
