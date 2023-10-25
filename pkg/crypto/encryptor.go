// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"fmt"
	"math"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/bodyaad"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/utils/rand"
)

func (e *encryptor) encrypt(source []byte, ec suite.EncryptionContext) ([]byte, *serialization.MessageHeader, error) {
	var b []byte
	b = make([]byte, len(source))
	copy(b, source)
	if len(source) <= 0 || len(b) <= 0 {
		return nil, nil, fmt.Errorf("empty source, %w", EncryptionErr)
	}
	buf := bytes.NewBuffer(b)
	if err := e.prepareMessage(buf, ec); err != nil {
		return nil, nil, err
	}

	if err := e.generateHeaderAuth(); err != nil {
		return nil, nil, err
	}

	if err := e.encryptBody(buf); err != nil {
		return nil, nil, err
	}

	// TODO andrew clean up derivedDataKey

	if e.signer != nil {
		signature, err := e.signer.sign()
		if err != nil {
			return nil, nil, err
		}
		footer, err := serialization.MessageFooter.NewFooter(e.algorithm, signature)
		if err != nil {
			return nil, nil, err
		}
		if err = e.updateCiphertextBuf(footer.Bytes()); err != nil {
			return nil, nil, err
		}
	}

	var ciphertext []byte
	ciphertext = make([]byte, e.ciphertextBuf.Len())
	_, err := e.ciphertextBuf.Read(ciphertext)
	if err != nil {
		return nil, nil, err
	}

	e.ciphertextBuf.Reset()

	return ciphertext, e.header, nil
}

func (e *encryptor) prepareMessage(plaintextBuffer *bytes.Buffer, ec suite.EncryptionContext) error {
	// check why we need ValidatePolicyOnEncrypt
	// here and: encryptionsdk/materials/manager.go:47
	if err := policy.Commitment.ValidatePolicyOnEncrypt(e.config.CommitmentPolicy(), e.algorithm); err != nil {
		return err
	}

	emr := materials.EncryptionMaterialsRequest{
		EncryptionContext: ec,
		FrameLength:       e.frameLength,
		PlaintextRoStream: nil,
		Algorithm:         e.algorithm,
		PlaintextLength:   plaintextBuffer.Len(),
		CommitmentPolicy:  e.config.CommitmentPolicy(),
	}

	encMaterials, err := e.cmm.GetEncryptionMaterials(emr)
	if err != nil {
		return fmt.Errorf("%w: failed cmm.GetEncryptionMaterials", EncryptionErr)
	}
	if len(encMaterials.EncryptedDataKeys()) > e.config.MaxEncryptedDataKeys() {
		return fmt.Errorf("%w: max encrypted data keys exceeded", EncryptionErr)
	}

	if e.algorithm.IsSigning() {
		e.signer = newSigner(e.algorithm, encMaterials.SigningKey())
	}

	// TODO validate frame length https://github.com/aws/aws-encryption-sdk-python/blob/93f01d655d6bce704bd8779cc9c4acb5f96b980c/src/aws_encryption_sdk/internal/utils/__init__.py#L44

	messageID, err := rand.CryptoRandomBytes(e.algorithm.MessageIDLen())
	if err != nil {
		return fmt.Errorf("%w: messageID error", EncryptionErr)
	}

	derivedDataKey, err := deriveDataEncryptionKey(encMaterials.DataEncryptionKey(), e.algorithm, messageID)
	if err != nil {
		return fmt.Errorf("%w: key derivation failed", EncryptionErr)
	}

	// TODO andrew clean up this after use
	e._derivedDataKey = derivedDataKey

	if err = e.generateHeader(messageID, encMaterials); err != nil {
		return err
	}

	return nil
}

func (e *encryptor) generateHeader(messageID []byte, encMaterials *materials.EncryptionMaterials) error {
	aadData := serialization.AAD.NewAADWithEncryptionContext(encMaterials.EncryptionContext())

	edks, err := serialization.EDK.FromEDKs(encMaterials.EncryptedDataKeys())
	if err != nil {
		return err
	}

	commitmentKey, err := calculateCommitmentKey(encMaterials.DataEncryptionKey(), e.algorithm, messageID)
	if err != nil {
		return err
	}

	params := serialization.MessageHeaderParams{
		AlgorithmSuite:     e.algorithm,
		MessageID:          messageID,
		AADData:            aadData,
		EncryptedDataKeys:  edks,
		ContentType:        suite.FramedContent,
		FrameLength:        e.frameLength,
		AlgorithmSuiteData: commitmentKey,
	}

	header, err := serialization.EncryptedMessageHeader.New(params)
	if err != nil {
		return err
	}
	e.header = header

	if err = e.updateBuffers(e.header.Bytes()); err != nil {
		return err
	}

	return nil
}

func (e *encryptor) generateHeaderAuth() error {
	headerAuthTag, err := e.aeadEncryptor.generateHeaderAuth(e._derivedDataKey, e.header.Bytes())
	if err != nil {
		return fmt.Errorf("%w: header auth error", err)
	}
	headerAuthData, err := serialization.MessageHeaderAuth.New(headerAuthTag)
	if err != nil {
		return fmt.Errorf("%w: header auth serialize error", err)
	}
	if err = e.updateBuffers(headerAuthData.Serialize()); err != nil {
		return err
	}
	return nil
}

func (e *encryptor) encryptBody(plaintextBuffer *bytes.Buffer) error {
	body, errBody := serialization.MessageBody.NewBody(e.header.AlgorithmSuite, e.frameLength)
	if errBody != nil {
		return errBody
	}

	framesToRead := math.Ceil(float64(plaintextBuffer.Len()) / float64(e.frameLength))

	// Check if an extra final frame is needed when the plaintextBuffer
	//  length is exactly divisible by the frame length
	if plaintextBuffer.Len()%e.frameLength == 0 {
		framesToRead++
	}

	calculateFrame := func() (int, bool) {
		if plaintextBuffer.Len() > e.frameLength {
			return e.frameLength, false
		} else if plaintextBuffer.Len() == e.frameLength {
			return e.frameLength, false
		} else {
			return plaintextBuffer.Len(), true
		}
	}

	for seqNum := 1; seqNum <= int(framesToRead); seqNum++ {
		bytesToRead, isFinal := calculateFrame()
		plaintext := plaintextBuffer.Next(bytesToRead)
		ciphertext, authTag, err := e.encryptFrame(seqNum, isFinal, plaintext)
		if err != nil {
			return err
		}
		if errFrame := body.AddFrame(isFinal, seqNum, constructIV(seqNum), len(plaintext), ciphertext, authTag); errFrame != nil {
			return errFrame
		}
	}

	if err := e.updateBuffers(body.Bytes()); err != nil {
		return err
	}
	return nil
}

func (e *encryptor) encryptFrame(seqNum int, isFinal bool, plaintext []byte) ([]byte, []byte, error) {
	associatedData := bodyaad.BodyAAD.ContentAADBytes(
		e.header.MessageID,
		bodyaad.BodyAAD.ContentString(suite.FramedContent, isFinal),
		seqNum,
		len(plaintext),
	)
	ciphertext, authTag, err := e.aeadEncryptor.encrypt(
		e._derivedDataKey,
		constructIV(seqNum),
		plaintext,
		associatedData,
	)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, authTag, nil
}

func (e *encryptor) updateCiphertextBuf(b []byte) error {
	if n, err := e.ciphertextBuf.Write(b); err != nil {
		log.Error().Err(err).Msg("CiphertextBuf update error")
		return err
	} else {
		log.Trace().Int("written", n).Msg("CiphertextBuf update")
	}

	return nil
}

func (e *encryptor) updateBuffers(b []byte) error {
	if err := e.updateCiphertextBuf(b); err != nil {
		return err
	}
	if e.signer != nil {
		e.signer.update(b)
	}

	return nil
}
