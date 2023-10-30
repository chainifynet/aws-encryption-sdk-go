// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog"
)

//nolint:unused
//goland:noinspection GoUnusedConst
const (
	colorBlack = iota + 30
	colorRed
	colorGreen
	colorYellow
	colorBlue
	colorMagenta
	colorCyan
	colorWhite

	colorBold             = 1
	colorDarkGray         = 90
	colorHighLighted      = 7
	colorHighLightedBlack = 40
	colorHighLightedRed   = 41
	colorHighLightedGreen = 42

	colorUnderScored      = 21
	colorUnderScoredLight = 4
	colorItalic           = 3

	colorBorderWhite = 51
)

func consoleFormatLevel(noColor bool) zerolog.Formatter {
	return func(i interface{}) string {
		var l string
		if ll, ok := i.(string); ok {
			switch ll {
			case zerolog.LevelTraceValue:
				l = colorize("TRACE", colorMagenta, noColor)
			case zerolog.LevelDebugValue:
				l = colorize("DEBUG", colorYellow, noColor)
			case zerolog.LevelInfoValue:
				l = colorize("INFO", colorGreen, noColor)
			case zerolog.LevelWarnValue:
				l = colorize("WARN", colorRed, noColor)
			case zerolog.LevelErrorValue:
				l = colorize(colorize("ERROR", colorRed, noColor), colorBold, noColor)
			case zerolog.LevelFatalValue:
				l = colorize(colorize("FATAL", colorRed, noColor), colorBold, noColor)
			case zerolog.LevelPanicValue:
				l = colorize(colorize("PANIC", colorRed, noColor), colorBold, noColor)
			default:
				l = colorize("???", colorBold, noColor)
			}
		} else {
			if i == nil {
				l = colorize("???", colorBold, noColor)
			} else {
				l = strings.ToUpper(fmt.Sprintf("%s", i))[0:3]
			}
		}
		return l
	}
}

func formatMessage(i interface{}) string {
	if i == nil {
		return ""
	}
	return colorize(i, colorYellow, false)
	//return fmt.Sprintf("%s", i)
}

func colorize(s interface{}, c int, disabled bool) string {
	if disabled {
		return fmt.Sprintf("%v", s)
	}
	return fmt.Sprintf("\x1b[%dm%v\x1b[0m\t", c, s)
}

func FmtBytes(b []byte) string {
	if LogBytes {
		return fmt.Sprintf("%#v", b)
	}
	return fmt.Sprintf("%T (%d) cap(%d)", b, len(b), cap(b))
}

//goland:noinspection GoUnusedExportedFunction
func FmtBytesB(b []byte) string {
	return fmt.Sprintf("(%d) = %#v", len(b), b)
}

func FmtHex(msg string, b []byte) func() string {
	columnBytes := 4
	rowColumns := 4
	return func() string {
		var buf strings.Builder
		buf.Grow(len(b)*2 + (len(b) / columnBytes) + (len(b) / rowColumns))
		cb := 1
		rc := 1
		for _, b2 := range b {
			//if i > 0 {
			_, _ = fmt.Fprintf(&buf, "%02X", b2)
			if cb == columnBytes {
				if rc == rowColumns {
					buf.WriteString("\n")
					cb = 1
					rc = 1
					continue
				}
				buf.WriteString(" ")
				cb = 1
				rc++
				continue
			}
			cb++
			//}
		}
		//fmt.Printf("cap: %d, len: %d\n", buf.Cap(), buf.Len())
		res := buf.String()
		return fmt.Sprintf("%v \tHEX(%d):\n%s", msg, len(b), res)
		//return fmt.Sprintf("%v \tHEX:\t\t\x1b[%dm% X\x1b[0m", msg, colorBlue, b)
	}
}

//goland:noinspection GoUnusedExportedFunction
func FmtHexColor(msg string, b []byte) func() string {
	return func() string {
		return fmt.Sprintf("%v \tHEX:\t\t\x1b[%dm% X\x1b[0m", msg, colorBlue, b)
	}
}

//goland:noinspection GoUnusedExportedFunction
func FmtBytesF(b []byte) (key, val string) {
	return "bytes", FmtBytes(b)
}
