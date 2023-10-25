// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
)

func TestAad_NewAAD(t *testing.T) {
	aad1 := AAD.NewAAD()

	log.Trace().
		Int("len", aad1.Len()).
		Str("bytes", logger.FmtBytes(aad1.Bytes())).
		Stringer("obj", aad1).
		Msg("empty AAD")

	assert.Equal(t, 0, aad1.Len())
	assert.Equal(t, []byte(nil), aad1.Bytes())

	if err := aad1.addKeyValue("test", "testing"); err != nil {
		panic(err)
	}

	log.Trace().
		Int("len", aad1.Len()).
		Str("bytes", logger.FmtBytes(aad1.Bytes())).
		Stringer("obj", aad1).
		Msg("AAD")

	var aad1Expected = []byte{0x0, 0x1, 0x0, 0x4, 0x74, 0x65, 0x73, 0x74, 0x0, 0x7, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67}
	assert.Equal(t, len(aad1Expected), aad1.Len())
	assert.Equal(t, aad1Expected, aad1.Bytes())

	aad1Bytes := AAD.FromBuffer(bytes.NewBuffer(aad1Expected))

	log.Trace().
		Stringer("obj", aad1Bytes).
		Int("len", aad1Bytes.Len()).
		Str("bytes", logger.FmtBytes(aad1Bytes.Bytes())).
		Msg("AAD aad1Bytes")

	assert.Equal(t, len(aad1Expected), aad1Bytes.Len())
	assert.Equal(t, aad1Expected, aad1Bytes.Bytes())

	var aad1ExpectedCopy []byte
	aad1ExpectedCopy = make([]byte, len(aad1Expected))
	copy(aad1ExpectedCopy, aad1Expected)
	buf := bytes.NewBuffer(aad1ExpectedCopy)

	log.Trace().Int("cap", buf.Cap()).Int("len", buf.Len()).
		Msg("Initial Buffer")

	assert.Equal(t, len(aad1Expected), buf.Len())
	assert.Equal(t, len(aad1Expected), buf.Cap())

	aad1BufferBytes := AAD.FromBuffer(buf)

	assert.Equal(t, 0, buf.Len())
	assert.Equal(t, aad1BufferBytes.Len(), buf.Cap())

	assert.Equal(t, len(aad1Expected), aad1BufferBytes.Len())
	assert.Equal(t, aad1Expected, aad1BufferBytes.Bytes())

	log.Trace().Int("cap", buf.Cap()).Int("len", buf.Len()).
		Msg("After Buffer")

	log.Trace().
		Stringer("obj", aad1BufferBytes).
		Int("len", aad1BufferBytes.Len()).
		Str("bytes", logger.FmtBytes(aad1BufferBytes.Bytes())).
		Msg("AAD aad1BufferBytes")

	// finals and most reliable
	buf2 := bytes.NewBuffer(aad1.Bytes())
	aad2 := AAD.FromBuffer(buf2)

	assert.Equal(t, aad1.Len(), aad2.Len())
	assert.Equal(t, aad1.Bytes(), aad2.Bytes())

	log.Trace().
		Stringer("obj", aad2).
		Int("len", aad2.Len()).
		Str("bytes", logger.FmtBytes(aad2.Bytes())).
		Msg("AAD aad2")

	aad3 := AAD.FromBuffer(bytes.NewBuffer(aad1.Bytes()))

	assert.Equal(t, aad1.Len(), aad3.Len())
	assert.Equal(t, aad1.Bytes(), aad3.Bytes())

	log.Trace().
		Stringer("obj", aad3).
		Int("len", aad3.Len()).
		Str("bytes", logger.FmtBytes(aad3.Bytes())).
		Msg("AAD aad3")
}

func TestAad_NewAADWithEncryptionContext(t *testing.T) {
	var aad1Expected = []byte{0x0, 0x1, 0x0, 0x4, 0x74, 0x65, 0x73, 0x74, 0x0, 0x7, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67}

	encryptionContext := map[string]string{
		"test": "testing",
	}

	aad1withEmptyEncryptionContext := AAD.NewAADWithEncryptionContext(map[string]string{})
	assert.Equal(t, 0, aad1withEmptyEncryptionContext.Len())
	assert.Equal(t, 0, len(aad1withEmptyEncryptionContext.kv))
	assert.Equal(t, []byte(nil), aad1withEmptyEncryptionContext.Bytes())

	aad1 := AAD.NewAADWithEncryptionContext(encryptionContext)
	log.Trace().
		Stringer("obj", aad1).
		Int("len", aad1.Len()).
		Str("bytes", logger.FmtBytes(aad1.Bytes())).
		Msg("AAD aad1")

	assert.Equal(t, len(aad1Expected), aad1.Len())
	assert.Equal(t, len(encryptionContext), len(aad1.kv))
	assert.Equal(t, aad1Expected, aad1.Bytes())

	encryptionContext2 := map[string]string{
		"test": "testing",
		"cert": "mops",
		"abra": "abracadabra",
	}

	var aad2Expected = []byte{0x0, 0x3, 0x0, 0x4, 0x61, 0x62, 0x72, 0x61, 0x0, 0xb, 0x61, 0x62, 0x72, 0x61, 0x63, 0x61, 0x64, 0x61, 0x62, 0x72, 0x61, 0x0, 0x4, 0x63, 0x65, 0x72, 0x74, 0x0, 0x4, 0x6d, 0x6f, 0x70, 0x73, 0x0, 0x4, 0x74, 0x65, 0x73, 0x74, 0x0, 0x7, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67}

	aad2 := AAD.NewAADWithEncryptionContext(encryptionContext2)
	log.Trace().
		Stringer("obj", aad2).
		Int("len", aad2.Len()).
		Str("bytes", logger.FmtBytes(aad2.Bytes())).
		Msg("AAD aad2")

	assert.Equal(t, len(aad2Expected), aad2.Len())
	assert.Equal(t, len(encryptionContext2), len(aad2.kv))
	assert.Equal(t, aad2Expected, aad2.Bytes())

	// finals and most reliable
	buf2 := bytes.NewBuffer(aad2.Bytes())
	log.Trace().Int("cap", buf2.Cap()).Int("len", buf2.Len()).
		Msg("Initial Buffer")
	assert.Equal(t, len(aad2Expected), buf2.Len())
	assert.Equal(t, len(aad2Expected), buf2.Cap())

	aad3 := AAD.FromBuffer(buf2)

	log.Trace().Int("cap", buf2.Cap()).Int("len", buf2.Len()).
		Msg("After Buffer")
	assert.Equal(t, 0, buf2.Len())
	assert.Equal(t, aad3.Len(), buf2.Cap())

	assert.Equal(t, aad2.Len(), aad3.Len())
	assert.Equal(t, len(aad2.kv), len(aad3.kv))
	assert.Equal(t, aad2.Bytes(), aad3.Bytes())

	log.Trace().
		Stringer("obj", aad3).
		Int("len", aad3.Len()).
		Str("bytes", logger.FmtBytes(aad3.Bytes())).
		Msg("AAD aad3")

	aad4 := AAD.FromBuffer(bytes.NewBuffer(aad2.Bytes()))

	assert.Equal(t, aad2.Len(), aad4.Len())
	assert.Equal(t, len(aad2.kv), len(aad4.kv))
	assert.Equal(t, aad2.Bytes(), aad4.Bytes())

	log.Trace().
		Stringer("obj", aad4).
		Int("len", aad4.Len()).
		Str("bytes", logger.FmtBytes(aad4.Bytes())).
		Msg("AAD aad4")
}
