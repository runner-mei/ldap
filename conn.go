// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This package provides LDAP client functions.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/mmitton/asn1-ber"
)

// LDAP Connection
type Conn struct {
	isClosed        bool
	next_message_id uint64
	conn            net.Conn
	isSSL           bool
	Debug           bool
}

// Dial connects to the given address on the given network using net.Dial
// and then returns a new Conn for the connection.
func Dial(network, addr string) (*Conn, *Error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	return newConn(c), nil
}

// Dial connects to the given address on the given network using net.Dial
// and then sets up SSL connection and returns a new Conn for the connection.
func DialSSL(network, addr string) (*Conn, *Error) {
	c, err := tls.Dial(network, addr, nil)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := newConn(c)
	conn.isSSL = true
	return conn, nil
}

// Dial connects to the given address on the given network using net.Dial
// and then starts a TLS session and returns a new Conn for the connection.
func DialTLS(network, addr string) (*Conn, *Error) {
	c, err := net.Dial(network, addr)
	if err != nil {
		return nil, NewError(ErrorNetwork, err)
	}
	conn := newConn(c)
	err = conn.startTLS()
	if err != nil {
		conn.Close()
		return nil, NewError(ErrorNetwork, err)
	}
	return conn, nil
}

// NewConn returns a new Conn using conn for network I/O.
func newConn(conn net.Conn) *Conn {
	return &Conn{
		isClosed: false,
		conn:     conn,
		isSSL:    false,
		Debug:    false,
	}
}

// Close closes the connection.
func (l *Conn) Close() {
	if !l.isClosed {
		l.conn.Close()
		l.isClosed = true
	}
}

// Returns the next available messageID
func (l *Conn) nextMessageID() uint64 {
	l.next_message_id++
	return l.next_message_id
}

// StartTLS sends the command to start a TLS session and then creates a new TLS Client
func (l *Conn) startTLS() *Error {
	request_id := l.nextMessageID()

	if l.isSSL {
		return NewError(ErrorNetwork, errors.New("Already encrypted"))
	}

	request_packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	request_packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, request_id, "MessageID"))
	startTLS := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationExtendedRequest, nil, "Start TLS")
	startTLS.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, "1.3.6.1.4.1.1466.20037", "TLS Extended Command"))
	request_packet.AppendChild(startTLS)
	if l.Debug {
		ber.PrintPacket(request_packet)
	}

	_, err := l.conn.Write(request_packet.Bytes())
	if err != nil {
		return NewError(ErrorNetwork, err)
	}

	response_packet, err := ber.ReadPacket(l.conn)
	if err != nil {
		return NewError(ErrorNetwork, err)
	}
	// if response_id != request_id {
	// 	return NewError(LDAPResultProtocolError, "reponse id is not expected.")
	// }

	if l.Debug {
		if err := addLDAPDescriptions(response_packet); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(response_packet)
	}

	if response_packet.Children[1].Children[0].Value.(uint64) == 0 {
		conn := tls.Client(l.conn, nil)
		l.isSSL = true
		l.conn = conn
	}

	return nil
}

func (l *Conn) send(message *ber.Packet) error {
	buf := message.Bytes()
	for len(buf) > 0 {
		n, err := l.conn.Write(buf)
		if err != nil {
			if l.Debug {
				fmt.Printf("Error Sending Message: %s\n", err)
			}
			return err
		}
		if n == len(buf) {
			break
		}
		buf = buf[n:]
	}
	return nil
}
func (l *Conn) read() (uint64, *ber.Packet, error) {
	p, err := ber.ReadPacket(l.conn)
	if err != nil {
		return 0, p, err
	}
	return p.Children[0].Value.(uint64), p, nil
}
