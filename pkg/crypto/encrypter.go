// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"context"
	"fmt"
	"math"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto/signature"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/bodyaad"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/keyderivation"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

func (e *encrypter) encrypt(ctx context.Context, source []byte, ec suite.EncryptionContext) ([]byte, format.MessageHeader, error) {
	var b []byte
	b = make([]byte, len(source))
	copy(b, source)
	if len(source) == 0 || len(b) == 0 {
		return nil, nil, fmt.Errorf("empty source")
	}
	buf := bytes.NewBuffer(b)
	if err := e.prepareMessage(ctx, buf, ec); err != nil {
		return nil, nil, fmt.Errorf("prepare message error: %w", err)
	}

	if err := e.generateHeaderAuth(); err != nil {
		return nil, nil, fmt.Errorf("encrypt error: %w", err)
	}

	if err := e.encryptBody(buf); err != nil {
		return nil, nil, fmt.Errorf("encrypt error: %w", err)
	}

	// TODO andrew clean up derivedDataKey

	if e.signer != nil {
		sign, err := e.signer.Sign()
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt sign error: %w", err)
		}
		footer, err := serialization.MessageFooter.NewFooter(e.algorithm, sign)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt sign error: %w", err)
		}
		if errBuf := e.updateCiphertextBuf(footer.Bytes()); errBuf != nil {
			return nil, nil, errBuf // already wrapped in updateCiphertextBuf
		}
	}

	var ciphertext []byte
	ciphertext = make([]byte, e.ciphertextBuf.Len())
	_, err := e.ciphertextBuf.Read(ciphertext)
	if err != nil {
		return nil, nil, fmt.Errorf("ciphertext read error: %w", err)
	}

	e.ciphertextBuf.Reset()

	return ciphertext, e.header, nil
}

func (e *encrypter) prepareMessage(ctx context.Context, plaintextBuffer *bytes.Buffer, ec suite.EncryptionContext) error {
	if err := policy.ValidateOnEncrypt(e.config.CommitmentPolicy(), e.algorithm); err != nil {
		return err // just return err
	}

	emr := model.EncryptionMaterialsRequest{
		EncryptionContext: ec,
		Algorithm:         e.algorithm,
		PlaintextLength:   plaintextBuffer.Len(),
	}

	encMaterials, err := e.cmm.GetEncryptionMaterials(ctx, emr)
	if err != nil {
		return fmt.Errorf("encrypt materials: %w", err)
	}
	if len(encMaterials.EncryptedDataKeys()) > e.config.MaxEncryptedDataKeys() {
		return fmt.Errorf("materials: max encrypted data keys exceeded")
	}

	if e.algorithm.IsSigning() {
		e.signer = signature.NewECCSigner(
			e.algorithm.Authentication.HashFunc,
			e.algorithm.Authentication.Algorithm,
			e.algorithm.Authentication.SignatureLen,
			encMaterials.SigningKey(),
		)
	}

	// TODO validate frame length https://github.com/aws/aws-encryption-sdk-python/blob/93f01d655d6bce704bd8779cc9c4acb5f96b980c/src/aws_encryption_sdk/internal/utils/__init__.py#L44

	messageID, err := rand.CryptoRandomBytes(e.algorithm.MessageIDLen())
	if err != nil {
		return fmt.Errorf("messageID error: %w", err)
	}

	derivedDataKey, err := keyderivation.DeriveDataEncryptionKey(encMaterials.DataEncryptionKey().DataKey(), e.algorithm, messageID)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	// TODO andrew clean up this after use
	e._derivedDataKey = derivedDataKey

	if errHeader := e.generateHeader(messageID, encMaterials); errHeader != nil {
		return fmt.Errorf("generate header error: %w", errHeader)
	}

	return nil
}

func (e *encrypter) generateHeader(messageID []byte, encMaterials model.EncryptionMaterial) error {
	edks, err := serialization.EDK.FromEDKs(encMaterials.EncryptedDataKeys())
	if err != nil {
		return fmt.Errorf("EDK error: %w", err)
	}

	var commitmentKey []byte
	if e.algorithm.IsCommitting() {
		commitmentKey, err = keyderivation.CalculateCommitmentKey(encMaterials.DataEncryptionKey().DataKey(), e.algorithm, messageID)
		if err != nil {
			return fmt.Errorf("calculate commitment key error: %w", err)
		}
	}

	params := serialization.HeaderParams{
		AlgorithmSuite:     e.algorithm,
		MessageID:          messageID,
		EncryptionContext:  encMaterials.EncryptionContext(),
		EncryptedDataKeys:  edks,
		ContentType:        suite.FramedContent,
		FrameLength:        e.frameLength,
		AlgorithmSuiteData: commitmentKey,
	}

	header, err := serialization.NewHeader(params)
	if err != nil {
		return fmt.Errorf("header error: %w", err)
	}
	e.header = header

	if errBuf := e.updateBuffers(e.header.Bytes()); errBuf != nil { //nolint:revive
		return errBuf
	}

	return nil
}

func (e *encrypter) generateHeaderAuth() error {
	headerAuthTag, iv, err := e.aeadEncrypter.GenerateHeaderAuth(e._derivedDataKey, e.header.Bytes())
	if err != nil {
		return fmt.Errorf("header auth error: %w", err)
	}
	headerAuthData, err := serialization.NewHeaderAuth(e.header.Version(), iv, headerAuthTag)
	if err != nil {
		return fmt.Errorf("header auth serialize error: %w", err)
	}
	if errBuf := e.updateBuffers(headerAuthData.Bytes()); errBuf != nil {
		return errBuf // wrapped already in updateCiphertextBuf
	}
	return nil
}

func (e *encrypter) encryptBody(plaintextBuffer *bytes.Buffer) error {
	body, errBody := serialization.MessageBody.NewBody(e.header.AlgorithmSuite(), e.frameLength)
	if errBody != nil {
		return fmt.Errorf("body error: %w", errBody)
	}

	framesToRead := math.Ceil(float64(plaintextBuffer.Len()) / float64(e.frameLength))

	// Check if an extra final frame is needed when the plaintextBuffer
	//  length is exactly divisible by the frame length
	if plaintextBuffer.Len()%e.frameLength == 0 {
		framesToRead++
	}

	calculateFrame := func() (int, bool) {
		if plaintextBuffer.Len() > e.frameLength { //nolint:gocritic
			return e.frameLength, false
		} else if plaintextBuffer.Len() == e.frameLength {
			return e.frameLength, false
		} else { //nolint:revive
			return plaintextBuffer.Len(), true
		}
	}

	for seqNum := 1; seqNum <= int(framesToRead); seqNum++ {
		bytesToRead, isFinal := calculateFrame()
		plaintext := plaintextBuffer.Next(bytesToRead)
		iv := e.aeadEncrypter.ConstructIV(seqNum)
		ciphertext, authTag, err := e.encryptFrame(seqNum, isFinal, iv, plaintext)
		if err != nil {
			return err
		}
		if errFrame := body.AddFrame(isFinal, seqNum, iv, len(plaintext), ciphertext, authTag); errFrame != nil {
			return fmt.Errorf("body frame error: %w", errFrame)
		}
	}

	return e.updateBuffers(body.Bytes())
}

func (e *encrypter) encryptFrame(seqNum int, isFinal bool, iv, plaintext []byte) ([]byte, []byte, error) {
	contentString, err := bodyaad.ContentString(suite.FramedContent, isFinal)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt frame error: %w", err)
	}
	associatedData := bodyaad.ContentAADBytes(
		e.header.MessageID(),
		contentString,
		seqNum,
		len(plaintext),
	)
	ciphertext, authTag, err := e.aeadEncrypter.Encrypt(
		e._derivedDataKey,
		iv,
		plaintext,
		associatedData,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("encrypt frame error: %w", err)
	}
	return ciphertext, authTag, nil
}

func (e *encrypter) updateCiphertextBuf(b []byte) error {
	_, err := e.ciphertextBuf.Write(b)
	if err != nil {
		return fmt.Errorf("ciphertext buffer write error: %w", err)
	}

	return nil
}

func (e *encrypter) updateBuffers(b []byte) error {
	if err := e.updateCiphertextBuf(b); err != nil {
		return err
	}
	if e.signer != nil {
		_, err := e.signer.Write(b)
		if err != nil {
			return fmt.Errorf("signer write error: %w", err)
		}
	}

	return nil
}
