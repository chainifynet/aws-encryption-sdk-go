// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package serialization

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/conv"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
)

const edkLenFields = int(3)

type providerIdentity string

const (
	awsKmsProviderID providerIdentity = "aws-kms"
)

var EDK = edk{ //nolint:gochecknoglobals
	ProviderID: awsKmsProviderID, // TODO deprecate this field
	LenFields:  edkLenFields,
}

type edk struct {
	ProviderID providerIdentity // TODO deprecate this field
	LenFields  int
}

var (
	ErrMaxEncryptedDataKeys = errors.New("maximum number of encrypted data keys")
	ErrMinEncryptedDataKeys = errors.New("minimum number of encrypted data keys is 1")
	errEDK                  = errors.New("EDK error")
)

type encryptedDataKey struct {
	providerIDLen       int              // 2, lenFieldBytes, providerIDLen is length of providerID, always present.
	providerID          providerIdentity // string bytes, only awsKmsProviderID supported as providerID, always present.
	providerInfoLen     int              // 2, lenFieldBytes, providerInfoLen is length of providerInfo, always present.
	providerInfo        string           // string bytes, providerInfo usually is KMS Key ID ARN, not an alias!
	encryptedDataKeyLen int              // 2, lenFieldBytes, encryptedDataKeyLen is length of encryptedDataKey
	encryptedDataKey    []byte           // bytes, encryptedDataKey is encrypted data key content bytes
}

func newEDK(providerID providerIdentity, providerInfo string, encryptedDataKeyData []byte) (*encryptedDataKey, error) {
	if strings.HasPrefix(string(providerID), "aws") && providerID != awsKmsProviderID {
		return nil, fmt.Errorf("providerID %s is not supported: %w", providerID, errEDK)
	}

	if strings.HasPrefix(providerInfo, "aws:") && providerID != awsKmsProviderID {
		return nil, fmt.Errorf("providerInfo %s is not supported: %w", providerInfo, errEDK)
	}

	if len(providerInfo) > math.MaxUint32 {
		return nil, fmt.Errorf("providerInfo is too large, out of range MaxUint32: %w", errEDK)
	}

	return &encryptedDataKey{
		providerIDLen:       len(providerID),
		providerID:          providerID,
		providerInfoLen:     len(providerInfo),
		providerInfo:        providerInfo,
		encryptedDataKeyLen: len(encryptedDataKeyData),
		encryptedDataKey:    encryptedDataKeyData,
	}, nil
}

func (edk encryptedDataKey) ProviderID() string {
	return string(edk.providerID)
}

func (edk encryptedDataKey) ProviderInfo() string {
	return edk.providerInfo
}

func (edk encryptedDataKey) EncryptedDataKey() []byte {
	return edk.encryptedDataKey
}

func (edk encryptedDataKey) String() string {
	return fmt.Sprintf("ID: %s, Info: %s, Data: %d", edk.providerID, edk.providerInfo, len(edk.encryptedDataKey))
}

func (edk encryptedDataKey) Len() int {
	return (edkLenFields * lenFieldBytes) +
		edk.providerIDLen +
		edk.providerInfoLen +
		edk.encryptedDataKeyLen
}

func (edk encryptedDataKey) Bytes() []byte {
	var buf []byte
	buf = make([]byte, 0, edk.Len())
	buf = append(buf, conv.FromInt.Uint16BigEndian(edk.providerIDLen)...)
	buf = append(buf, []byte(edk.providerID)...)
	buf = append(buf, conv.FromInt.Uint16BigEndian(edk.providerInfoLen)...)
	buf = append(buf, []byte(edk.providerInfo)...)
	buf = append(buf, conv.FromInt.Uint16BigEndian(edk.encryptedDataKeyLen)...)
	buf = append(buf, edk.encryptedDataKey...)
	return buf
}

func (e edk) AsKeys(msgEDKs []format.MessageEDK) []model.EncryptedDataKeyI {
	edks := make([]model.EncryptedDataKeyI, 0, len(msgEDKs))
	for _, k := range msgEDKs {
		ek := model.NewEncryptedDataKey(
			model.WithKeyMeta(k.ProviderID(), k.ProviderInfo()),
			k.EncryptedDataKey(),
		)
		edks = append(edks, ek)
	}
	return edks
}

func (e edk) validateMinMaxEDKs(k, m int) error {
	if k <= 0 {
		return fmt.Errorf("reached limit: %w", ErrMinEncryptedDataKeys)
	}
	if k > m {
		return fmt.Errorf("reached max limit: %w", ErrMaxEncryptedDataKeys)
	}
	return nil
}

func (e edk) fromBufferWithCount(buf *bytes.Buffer) (int, []format.MessageEDK, error) {
	if buf.Len() < countFieldBytes {
		return 0, nil, fmt.Errorf("deserialize encrypted data keys count: %w", errEDK)
	}

	encryptedDataKeyCount, _ := fieldReader.ReadCountField(buf)
	if encryptedDataKeyCount <= 0 {
		return 0, nil, fmt.Errorf("encrypted data keys not found in message header: %w", errEDK)
	}

	var edks []format.MessageEDK
	for i := 0; i < encryptedDataKeyCount; i++ {
		encDataKey, err := deserializeEDK(buf)
		if err != nil {
			return 0, nil, fmt.Errorf("cant deserialize expected encrypted data key: %w", errors.Join(errEDK, err))
		}
		edks = append(edks, encDataKey)
	}

	return encryptedDataKeyCount, edks, nil
}

func (e edk) FromEDKs(list []model.EncryptedDataKeyI) ([]format.MessageEDK, error) {
	edks := make([]format.MessageEDK, 0, len(list))
	for _, keyI := range list {
		encDataKey, err := newEDK(providerIdentity(keyI.KeyProvider().ProviderID), keyI.KeyProvider().KeyID, keyI.EncryptedDataKey())
		if err != nil {
			return nil, err
		}
		edks = append(edks, encDataKey)
	}
	return edks, nil
}

func deserializeEDK(buf *bytes.Buffer) (*encryptedDataKey, error) {
	providerIDLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant deserialize encrypted data key providerIDLen, %w", err)
	}
	if buf.Len() < providerIDLen {
		return nil, fmt.Errorf("cant deserialize encrypted data key providerID")
	}
	providerID := buf.Next(providerIDLen)

	providerInfoLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant deserialize encrypted data key providerInfoLen, %w", err)
	}
	if buf.Len() < providerInfoLen {
		return nil, fmt.Errorf("cant deserialize encrypted data key providerInfo")
	}
	providerInfo := buf.Next(providerInfoLen)

	encryptedDataKeyLen, err := fieldReader.ReadLenField(buf)
	if err != nil {
		return nil, fmt.Errorf("cant deserialize encrypted data key encryptedDataKeyLen, %w", err)
	}
	if buf.Len() < encryptedDataKeyLen {
		return nil, fmt.Errorf("cant deserialize encrypted data key encryptedDataKeyData")
	}
	encryptedDataKeyData := buf.Next(encryptedDataKeyLen)

	return newEDK(providerIdentity(providerID), string(providerInfo), encryptedDataKeyData)
}
