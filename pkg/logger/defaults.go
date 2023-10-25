// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package logger

import "github.com/rs/zerolog"

type OutputFormat string

const (
	ConsoleOutput OutputFormat = "console"
	Default       OutputFormat = "Stderr"
)

const (
	LogLevel  = zerolog.DebugLevel
	LogOutput = ConsoleOutput
	LogBytes  = false
)
