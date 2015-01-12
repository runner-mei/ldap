// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// File contains Bind functionality
package ldap

import (
	"errors"

	"github.com/mmitton/asn1-ber"
)

func (l *Conn) Bind(username, password string) *Error {
	request_id := l.nextMessageID()

	request_packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	request_packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, request_id, "MessageID"))
	bindRequest := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindRequest, nil, "Bind Request")
	bindRequest.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimative, ber.TagInteger, 3, "Version"))
	bindRequest.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimative, ber.TagOctetString, username, "User Name"))
	bindRequest.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimative, 0, password, "Password"))
	request_packet.AppendChild(bindRequest)

	if l.Debug {
		ber.PrintPacket(request_packet)
	}

	if err := l.send(request_packet); err != nil {
		return NewError(ErrorNetwork, err)
	}

	response_id, response_body, err := l.read()
	if nil != err {
		return NewError(ErrorNetwork, err)
	}

	if request_id != response_id {
		return NewError(ErrorNetwork, errors.New("message id is not excepted."))
	}

	if l.Debug {
		if err := addLDAPDescriptions(response_body); err != nil {
			return NewError(ErrorDebugging, err)
		}
		ber.PrintPacket(response_body)
	}

	result_code, result_description := getLDAPResultCode(response_body)
	if result_code != 0 {
		return NewError(result_code, errors.New(result_description))
	}
	return nil
}
