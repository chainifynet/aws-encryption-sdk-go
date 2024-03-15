// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package decrypter

import (
	"bytes"
	"context"
	"crypto/hmac"
	"errors"
	"fmt"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/crypto"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/crypto/signature"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/bodyaad"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/encryption"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/internal/utils/keyderivation"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/model/format"
)

// ErrInvalidMessage is returned when the message format is invalid.
var ErrInvalidMessage = errors.New("invalid message format")

type Decrypter struct {
	cmm             model.CryptoMaterialsManager
	cfg             crypto.DecrypterConfig
	aeadDecrypter   model.AEADDecrypter
	deser           format.Deserializer
	header          format.MessageHeader
	verifier        signature.Verifier
	verifierFn      signature.VerifierFunc
	_derivedDataKey []byte
}

func New(cfg crypto.DecrypterConfig, cmm model.CryptoMaterialsManager) model.DecryptionHandler {
	return &Decrypter{
		cmm:           cmm.GetInstance(),
		cfg:           cfg,
		aeadDecrypter: encryption.Gcm{},
		deser:         serialization.NewDeserializer(),
		verifierFn:    signature.NewECCVerifier,
	}
}

func (d *Decrypter) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, format.MessageHeader, error) {
	b, header, err := d.decryptData(ctx, ciphertext)
	if err != nil {
		d.reset(err)
		return nil, nil, fmt.Errorf("SDK error: %w", errors.Join(crypto.ErrDecryption, err))
	}
	d.reset(nil)
	return b, header, nil
}

// decryptData ciphertext decryption
func (d *Decrypter) decryptData(ctx context.Context, ciphertext []byte) ([]byte, format.MessageHeader, error) {
	var b []byte
	b = make([]byte, len(ciphertext))
	copy(b, ciphertext)
	if len(ciphertext) == 0 || len(b) == 0 {
		return nil, nil, fmt.Errorf("empty ciphertext")
	}

	// early stage check if cipher text contains needed first byte of message version
	// by doing this we avoid mistakes with base64 byte sequence
	if ciphertext[0] != firstByteEncryptedMessageV1 && ciphertext[0] != firstByteEncryptedMessageV2 {
		return nil, nil, fmt.Errorf("first byte does not contain message version: %w", ErrInvalidMessage)
	}
	buf := bytes.NewBuffer(b)

	if err := d.decryptHeader(ctx, buf); err != nil {
		return nil, nil, err
	}

	body, err := d.decryptBody(buf)
	if err != nil {
		return nil, nil, err
	}

	if d.verifier != nil {
		footer, errFooter := d.deser.DeserializeFooter(buf, d.header.AlgorithmSuite())
		if errFooter != nil {
			return nil, nil, errFooter
		}

		if errSig := d.verifier.Verify(footer.Signature()); errSig != nil {
			return nil, nil, errSig
		}
	}
	// TODO check if alg is non-signing, but footer has signature, return error

	return body, d.header, nil
}

func (d *Decrypter) decryptHeader(ctx context.Context, buf *bytes.Buffer) error {
	header, headerAuth, err := d.deser.DeserializeHeader(buf, d.cfg.ClientCfg.MaxEncryptedDataKeys())
	if err != nil {
		return err
	}

	if errPolicy := policy.ValidateOnDecrypt(d.cfg.ClientCfg.CommitmentPolicy(), header.AlgorithmSuite()); errPolicy != nil {
		return errPolicy
	}

	if header.AlgorithmSuite().IsSigning() {
		d.verifier = d.verifierFn(
			header.AlgorithmSuite().Authentication.HashFunc,
			header.AlgorithmSuite().Authentication.Algorithm,
		)
		if err := d.updateVerifier(header.Bytes()); err != nil {
			return err
		}
		if err := d.updateVerifier(headerAuth.Bytes()); err != nil {
			return err
		}
	}

	dmr := model.DecryptionMaterialsRequest{
		Algorithm:         header.AlgorithmSuite(),
		EncryptedDataKeys: serialization.EDK.AsKeys(header.EncryptedDataKeys()),
		EncryptionContext: header.AADData().EncryptionContext(),
	}

	decMaterials, err := d.cmm.DecryptMaterials(ctx, dmr)
	if err != nil {
		return fmt.Errorf("decrypt materials: %w", err)
	}

	if d.verifier != nil {
		if errLK := d.verifier.LoadECCKey(decMaterials.VerificationKey()); errLK != nil {
			return fmt.Errorf("decrypt verifier error: %w", errLK)
		}
	}

	derivedDataKey, err := keyderivation.DeriveDataEncryptionKey(decMaterials.DataKey().DataKey(), header.AlgorithmSuite(), header.MessageID())
	if err != nil {
		return fmt.Errorf("decrypt key derivation error: %w", err)
	}

	if header.AlgorithmSuite().IsCommitting() {
		expectedCommitmentKey, err := keyderivation.CalculateCommitmentKey(decMaterials.DataKey().DataKey(), header.AlgorithmSuite(), header.MessageID())
		if err != nil {
			return fmt.Errorf("decrypt calculate commitment key error: %w", err)
		}

		if ok := hmac.Equal(expectedCommitmentKey, header.AlgorithmSuiteData()); !ok {
			return fmt.Errorf("key commitment validation failed: key identity does not match the identity asserted in the message")
		}
	}

	if errHeaderAuth := d.aeadDecrypter.ValidateHeaderAuth(derivedDataKey, headerAuth.AuthData(), header.Bytes()); errHeaderAuth != nil {
		return fmt.Errorf("decrypt header auth error: %w", errHeaderAuth)
	}

	d._derivedDataKey = derivedDataKey
	d.header = header

	return nil
}

func (d *Decrypter) decryptBody(buf *bytes.Buffer) ([]byte, error) {
	body, err := d.deser.DeserializeBody(buf, d.header.AlgorithmSuite(), d.header.FrameLength())
	if err != nil {
		return nil, fmt.Errorf("deserialize body error: %w", err)
	}

	plaintext := new(bytes.Buffer)

	for _, frame := range body.Frames() {
		b, errFrame := d.decryptFrame(frame)
		if errFrame != nil {
			return nil, fmt.Errorf("decrypt frame error: %w", errFrame)
		}
		plaintext.Write(b)
	}

	var plaintextData []byte
	plaintextData = make([]byte, plaintext.Len())

	_, _ = plaintext.Read(plaintextData)
	plaintext.Reset()

	return plaintextData, nil
}

func (d *Decrypter) decryptFrame(frame format.BodyFrame) ([]byte, error) {
	contentString, err := bodyaad.ContentString(d.header.ContentType(), frame.IsFinal())
	if err != nil {
		return nil, fmt.Errorf("bodyaad error: %w", err)
	}
	associatedData := bodyaad.ContentAADBytes(
		d.header.MessageID(),
		contentString,
		frame.SequenceNumber(),
		len(frame.EncryptedContent()),
	)
	b, err := d.aeadDecrypter.Decrypt(
		d._derivedDataKey,
		frame.IV(),
		frame.EncryptedContent(),
		frame.AuthenticationTag(),
		associatedData,
	)
	if err != nil {
		return nil, fmt.Errorf("decrypt frame AEAD error: %w", err)
	}
	// if alg is signing, write each frame bytes to verifier to update message hash
	if d.verifier != nil {
		if err := d.updateVerifier(frame.Bytes()); err != nil {
			return nil, err
		}
	}
	return b, nil
}

func (d *Decrypter) updateVerifier(b []byte) error {
	if _, err := d.verifier.Write(b); err != nil {
		return fmt.Errorf("verifier write error: %w", err)
	}
	return nil
}

func (d *Decrypter) reset(err error) {
	d._derivedDataKey = nil
	if err != nil {
		d.header = nil
	}
}
