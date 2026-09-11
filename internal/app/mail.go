package app

import (
	"crypto/tls"
	"fmt"
	"html"
	"io"
	"net"
	"net/mail"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

type mailSender interface {
	SendVerification(to, username, verifyURL string) error
}

type smtpSender struct {
	host, port, username, password string
	from                           mail.Address
}

func newSMTPSender(c runtimeConfig) (*smtpSender, error) {
	from, err := mail.ParseAddress(c.smtpFromAddress)
	if err != nil || !strings.EqualFold(from.Address, c.smtpFromAddress) {
		return nil, fmt.Errorf("SMTP_FROM_ADDRESS must be a plain valid email address")
	}
	from.Name = c.smtpFromName
	return &smtpSender{host: c.smtpHost, port: c.smtpPort, username: c.smtpUsername, password: c.smtpPassword, from: *from}, nil
}

func (s *smtpSender) SendVerification(to, username, verifyURL string) error {
	recipient, err := mail.ParseAddress(to)
	if err != nil || !strings.EqualFold(recipient.Address, to) {
		return fmt.Errorf("invalid verification recipient")
	}
	subject := "Verify your Netriun Nexus email"
	plain := fmt.Sprintf("Hello %s,\n\nVerify your email to activate your Netriun Nexus workspace:\n%s\n\nThis link expires in 24 hours. If you did not create this account, you can ignore this email.\n", username, verifyURL)
	htmlBody := fmt.Sprintf("<p>Hello %s,</p><p>Verify your email to activate your Netriun Nexus workspace:</p><p><a href=\"%s\">Verify email address</a></p><p>This link expires in 24 hours. If you did not create this account, you can ignore this email.</p>", html.EscapeString(username), html.EscapeString(verifyURL))
	boundary := "nexus-verification-boundary"
	message := strings.Join([]string{
		"From: " + s.from.String(),
		"To: " + recipient.String(),
		"Subject: " + subject,
		"MIME-Version: 1.0",
		"Content-Type: multipart/alternative; boundary=" + boundary,
		"",
		"--" + boundary,
		"Content-Type: text/plain; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		plain,
		"--" + boundary,
		"Content-Type: text/html; charset=UTF-8",
		"Content-Transfer-Encoding: 8bit",
		"",
		htmlBody,
		"--" + boundary + "--",
		"",
	}, "\r\n")
	return s.send(recipient.Address, strings.NewReader(message))
}

func (s *smtpSender) send(to string, body io.Reader) error {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	connection, err := dialer.Dial("tcp", net.JoinHostPort(s.host, s.port))
	if err != nil {
		return err
	}
	client, err := smtp.NewClient(connection, s.host)
	if err != nil {
		connection.Close()
		return err
	}
	defer client.Close()
	if ok, _ := client.Extension("STARTTLS"); !ok {
		return fmt.Errorf("SMTP server does not offer STARTTLS")
	}
	if err = client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
		return err
	}
	if err = client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
		return err
	}
	if err = client.Mail(s.from.Address); err != nil {
		return err
	}
	if err = client.Rcpt(to); err != nil {
		return err
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err = io.Copy(writer, body); err != nil {
		writer.Close()
		return err
	}
	if err = writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

func verificationURL(origin, token string) string {
	return origin + "/verify-email?token=" + url.QueryEscape(token)
}
