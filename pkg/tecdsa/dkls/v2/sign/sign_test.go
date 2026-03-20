// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package sign

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dealer"
)

func TestSignFull(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.P256()} {
		curve := curve
		t.Run(curve.Name, func(t *testing.T) {
			t.Parallel()
			aliceDkg, bobDkg, err := dealer.GenerateAndDeal(curve)
			require.NoError(t, err)

			message := []byte("DKLS19 test message")

			alice := NewAlice(curve, sha3.New256(), aliceDkg)
			bob := NewBob(curve, sha3.New256(), bobDkg)

			aliceSeed, err := alice.Round1GenerateRandomSeed()
			require.NoError(t, err)

			r2, err := bob.Round2Initialize(aliceSeed)
			require.NoError(t, err)

			r3, err := alice.Round3Sign(message, r2)
			require.NoError(t, err)

			require.NoError(t, bob.Round4Final(message, r3))
			require.NotNil(t, bob.Signature)
			require.NotNil(t, bob.Signature.R)
			require.NotNil(t, bob.Signature.S)
		})
	}
}

func TestMultiplySubProtocol(t *testing.T) {
	t.Parallel()
	curve := curves.K256()
	aliceDkg, bobDkg, err := dealer.GenerateAndDeal(curve)
	require.NoError(t, err)

	sessionID := [32]byte{0x01}
	alpha := curve.Scalar.Random(rand.Reader)
	beta := curve.Scalar.Random(rand.Reader)
	expected := alpha.Mul(beta)

	sender, err := NewMultiplySender(aliceDkg.SeedOtResult, curve, sessionID)
	require.NoError(t, err)

	receiver, err := NewMultiplyReceiver(bobDkg.SeedOtResult, curve, sessionID)
	require.NoError(t, err)

	r1, err := receiver.Round1Initialize(beta)
	require.NoError(t, err)

	r2, err := sender.Round2Multiply(alpha, r1)
	require.NoError(t, err)

	require.NoError(t, receiver.Round3Multiply(r2))

	// δ_s + δ_r == α · β  (mod q)
	sum := sender.outputAdditiveShare.Add(receiver.outputAdditiveShare)
	require.Equal(t, expected.Bytes(), sum.Bytes())
}
