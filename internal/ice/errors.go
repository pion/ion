// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ice provides ICE, TURN, STUN services for Ion.
package ice

import "errors"

var errEmptySTUNEndpoint = errors.New("both stun tcp and udp endpoints are empty")

var errEmptyTURNEndpoint = errors.New("turn tcp, udp, and tls endpoints are empty")

var errEmptyRealm = errors.New("realm is empty")

var errEmptyTURNToken = errors.New("turn authentication token is empty")

var errEmptyTURNUserPwd = errors.New("turn authentication user or password is empty")

var errInvalidTURNAuth = errors.New("invalid turn authentication")

var errEmptyTLSCertKey = errors.New("tls cert or key is empty")

var errInvalidTLSVersion = errors.New("invalid TLS version")

var errInvalidPortRange = errors.New("invalid port range")
