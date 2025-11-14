// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateEndpoint(t *testing.T) {
	err := ValidateEndpoint("")
	require.NoError(t, err)

	err = ValidateEndpoint(":7000")
	require.NoError(t, err)

	err = ValidateEndpoint("localhost:7000")
	require.NoError(t, err)

	err = ValidateEndpoint("127.0.0.1:7000")
	require.NoError(t, err)

	err = ValidateEndpoint("127.0.0.1;7000")
	require.ErrorIs(t, err, ErrInvalidHostPort)
}
