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
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/silent"
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

// produceOTResults generates compact silent-OT seed material for Alice (receiver) and
// Bob (sender) without running the interactive DKG protocol — only safe inside a trusted
// dealer since the dealer sees both parties' material.
func produceOTResults(curve *curves.Curve) (*silent.ReceiverOutput, *silent.SenderOutput, error) {
	// Use an empty session ID — the dealer doesn't participate in a live transcript.
	sessionID := make([]byte, 32)

	senderOut, proof, err := silent.NewSender(curve, sessionID)
	if err != nil {
		return nil, nil, errors.Wrap(err, "DKLS19 dealer: silent OT sender")
	}
	receiverOut, err := silent.NewReceiver(curve, proof, sessionID)
	if err != nil {
		return nil, nil, errors.Wrap(err, "DKLS19 dealer: silent OT receiver")
	}
	return receiverOut, senderOut, nil
}
