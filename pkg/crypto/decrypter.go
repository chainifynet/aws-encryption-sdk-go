// Copyright Chainify Group LTD. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

package crypto

import (
	"bytes"
	"crypto/hmac"

	"github.com/pkg/errors"

	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/bodyaad"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/helpers/policy"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/logger"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/materials"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/serialization"
	"github.com/chainifynet/aws-encryption-sdk-go/pkg/suite"
)

// Decrypt ciphertext decryption
func (d *decrypter) decrypt(ciphertext []byte) ([]byte, error) {
	var b []byte
	b = make([]byte, len(ciphertext))
	copy(b, ciphertext)
	if len(ciphertext) <= 0 || len(b) <= 0 {
		return nil, errors.Wrap(InvalidMessage, "empty ciphertext")
	}

	// early stage check if cipher text contains needed first byte of message version
	// by doing this we avoid mistakes with base64 byte sequence
	if ciphertext[0] != byte(0x02) {
		return nil, errors.Wrap(InvalidMessage, "first byte does not contain message version")
	}
	buf := bytes.NewBuffer(b)

	if err := d.decryptHeader(buf); err != nil {
		return nil, err
	}

	body, err := d.decryptBody(buf)
	if err != nil {
		return nil, err
	}

	if d.verifier != nil {
		footer, errFooter := serialization.MessageFooter.FromBuffer(d.header.AlgorithmSuite, buf)
		if errFooter != nil {
			return nil, errFooter
		}

		if errSig := d.verifier.verify(footer.Signature); errSig != nil {
			return nil, errSig
		}
	}

	// TODO andrew return header on decryption
	return body, nil
}

func (d *decrypter) decryptHeader(buf *bytes.Buffer) error {
	header, headerAuth, err := serialization.DeserializeHeader(buf, d.config.MaxEncryptedDataKeys())
	if err != nil {
		return err
	}

	if err = policy.Commitment.ValidatePolicyOnDecrypt(d.config.CommitmentPolicy(), header.AlgorithmSuite); err != nil {
		return err
	}

	if header.AlgorithmSuite.IsSigning() {
		d.verifier = newVerifier(header.AlgorithmSuite)
		d.verifier.update(header.Bytes())
		d.verifier.update(headerAuth.Serialize())
	}

	log.Trace().
		Int("len", header.Len()).
		Str("bytes", logger.FmtBytes(header.Bytes())).
		Int("headerAuthLen", headerAuth.Len()).
		Str("headerAuthB", logger.FmtBytes(headerAuth.AuthData())).
		Msg("headers")

	dmr := materials.DecryptionMaterialsRequest{
		Algorithm:         header.AlgorithmSuite,
		EncryptedDataKeys: serialization.EDK.AsKeys(header.EncryptedDataKeys),
		EncryptionContext: header.AADData.AsEncryptionContext(),
		CommitmentPolicy:  d.config.CommitmentPolicy(),
	}

	decMaterials, err := d.cmm.DecryptMaterials(dmr)
	if err != nil {
		return errors.Wrap(err, "failed cmm.DecryptMaterials")
	}

	if d.verifier != nil {
		if errLK := d.verifier.loadECCVerificationKey(decMaterials.VerificationKey()); errLK != nil {
			return errLK
		}
	}

	derivedDataKey, err := deriveDataEncryptionKey(decMaterials.DataKey(), header.AlgorithmSuite, header.MessageID)
	if err != nil {
		return errors.Wrapf(DecryptionErr, "key derivation failed: %v", err)
	}

	if header.AlgorithmSuite.IsCommitting() {
		expectedCommitmentKey, err := calculateCommitmentKey(decMaterials.DataKey(), header.AlgorithmSuite, header.MessageID)
		if err != nil {
			return errors.Wrapf(DecryptionErr, "failed to calculate commitment key: %v", err)
		}

		if ok := hmac.Equal(expectedCommitmentKey, header.AlgorithmSuiteData); !ok {
			return errors.Wrap(DecryptionErr, "Key commitment validation failed. Key identity does not match the identity asserted in the message")
		}
	}

	if err = d.aeadDecrypter.validateHeaderAuth(derivedDataKey, headerAuth.AuthData(), header.Bytes()); err != nil {
		return err
	}

	if d._derivedDataKey != nil {
		return errors.New("derived data key already exists")
	}
	d._derivedDataKey = derivedDataKey

	if d.header != nil {
		return errors.New("header already exists")
	}
	d.header = header

	return nil
}

func (d *decrypter) decryptBody(buf *bytes.Buffer) ([]byte, error) {
	body, err := serialization.DeserializeBody(buf, d.header.AlgorithmSuite, d.header.FrameLength)
	if err != nil {
		return nil, err
	}

	plaintext := new(bytes.Buffer)
	readBytes := 0

	for _, frame := range body.Frames() {
		associatedData := bodyaad.BodyAAD.ContentAADBytes(
			d.header.MessageID,
			bodyaad.BodyAAD.ContentString(suite.FramedContent, frame.IsFinal()),
			frame.SequenceNumber(),
			len(frame.EncryptedContent()),
		)
		b, err := d.aeadDecrypter.decrypt(
			d._derivedDataKey,
			frame.IV(),
			frame.EncryptedContent(),
			frame.AuthenticationTag(),
			associatedData,
		)
		if err != nil {
			return nil, err
		}
		readBytes += len(b)
		plaintext.Write(b)
		// if alg is signing, write each frame bytes to verifier to update message hash
		if d.verifier != nil {
			d.verifier.update(frame.Bytes())
		}
	}

	if plaintext.Len() != readBytes {
		return nil, errors.New("malformed message body size")
	}

	var plaintextData []byte
	plaintextData = make([]byte, plaintext.Len())

	wb, err := plaintext.Read(plaintextData)
	if err != nil {
		return nil, errors.Wrapf(err, "malformed body message size")
	}
	if wb != readBytes {
		return nil, errors.Wrapf(err, "malformed body message size")
	}
	plaintext.Reset()

	return plaintextData, nil
}
