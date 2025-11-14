// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package utils provides utilities.
package utils

import (
	"errors"
	"fmt"
	"net"
)

var ErrInvalidHostPort = errors.New("invalid host port string")

func ValidateEndpoint(ep string) error {
	if ep == "" {
		return nil
	}
	if _, _, err := net.SplitHostPort(ep); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidHostPort, err)
	}

	return nil
}
