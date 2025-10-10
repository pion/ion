// SPDX-FileCopyrightText: 2025 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package core_test

import (
	"testing"

	"github.com/pion/ion/v2/internal/core"
	"github.com/stretchr/testify/require"
)

func TestHelloWorld(t *testing.T) {
	t.Parallel()
	require.Equal(t, "hello world", core.HelloWorld())
}
