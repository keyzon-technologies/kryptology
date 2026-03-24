// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package dealer implements key generation via a trusted dealer for DKLS19.
//
// WARNING: Running actual DKG is ALWAYS recommended over a trusted dealer.
// This function is provided solely for testing and bootstrapping purposes.
// Using it in production breaks the security guarantees of the two-party protocol
// because the dealer learns both key shares.
package dealer

import (
	"crypto/rand"

	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/ot/extension/kos"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
)

// GenerateAndDeal produces key material for Alice and Bob that matches the
// output of the DKLS19 DKG protocol.
//
// The joint public key is Q = (x_A + x_B)·G  (additive sharing).
func GenerateAndDeal(curve *curves.Curve) (*dkg.AliceOutput, *dkg.BobOutput, error) {
	aliceShare, bobShare, publicKey := produceKeyShares(curve)

	aliceOT, bobOT, err := produceOTResults(curve)
	if err != nil {
		return nil, nil, errors.Wrap(err, "DKLS19 dealer: producing OT results")
	}

	return &dkg.AliceOutput{
			PublicKey:      publicKey,
			SecretKeyShare: aliceShare,
			SeedOtResult:   aliceOT,
		}, &dkg.BobOutput{
			PublicKey:      publicKey,
			SecretKeyShare: bobShare,
			SeedOtResult:   bobOT,
		}, nil
}

// produceKeyShares samples x_A, x_B ← F_q and computes Q = (x_A + x_B)·G.
func produceKeyShares(curve *curves.Curve) (xA, xB curves.Scalar, Q curves.Point) {
	xA = curve.Scalar.Random(rand.Reader)
	xB = curve.Scalar.Random(rand.Reader)
	Q = curve.ScalarBaseMult(xA).Add(curve.ScalarBaseMult(xB))
	return xA, xB, Q
}

// produceOTResults generates seed OT material for Alice (receiver) and Bob (sender)
// without running the interactive protocol — only safe inside a trusted dealer.
func produceOTResults(curve *curves.Curve) (*simplest.ReceiverOutput, *simplest.SenderOutput, error) {
	// Initialise a receiver to get fresh random choice bits.
	receiver, err := simplest.NewReceiver(curve, kos.Kappa, [simplest.DigestSize]byte{})
	if err != nil {
		return nil, nil, errors.Wrap(err, "DKLS19 dealer: initialising OT receiver")
	}

	encryptionKeys := make([]simplest.OneTimePadEncryptionKeys, kos.Kappa)
	decryptionKeys := make([]simplest.OneTimePadDecryptionKey, kos.Kappa)

	for i := 0; i < kos.Kappa; i++ {
		if _, err = rand.Read(encryptionKeys[i][0][:]); err != nil {
			return nil, nil, errors.Wrap(err, "DKLS19 dealer: generating OT pad [0]")
		}
		if _, err = rand.Read(encryptionKeys[i][1][:]); err != nil {
			return nil, nil, errors.Wrap(err, "DKLS19 dealer: generating OT pad [1]")
		}
		// The receiver holds the key corresponding to its random choice bit.
		decryptionKeys[i] = encryptionKeys[i][receiver.Output.RandomChoiceBits[i]]
	}

	return &simplest.ReceiverOutput{
			PackedRandomChoiceBits:  receiver.Output.PackedRandomChoiceBits,
			RandomChoiceBits:        receiver.Output.RandomChoiceBits,
			OneTimePadDecryptionKey: decryptionKeys,
		}, &simplest.SenderOutput{
			OneTimePadEncryptionKeys: encryptionKeys,
		}, nil
}
