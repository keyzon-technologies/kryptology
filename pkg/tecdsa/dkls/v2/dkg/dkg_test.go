// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dkg

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
)

func TestDKGFull(t *testing.T) {
	t.Parallel()
	curveInstances := []*curves.Curve{
		curves.K256(),
		curves.P256(),
	}
	for _, curve := range curveInstances {
		alice := NewAlice(curve)
		bob := NewBob(curve)

		bobSeed, err := bob.Round1GenerateRandomSeed()
		require.NoError(t, err)

		r2Output, err := alice.Round2CommitToProof(bobSeed)
		require.NoError(t, err)

		bobProof, err := bob.Round3SchnorrProve(r2Output)
		require.NoError(t, err)

		aliceProof, err := alice.Round4VerifyAndReveal(bobProof)
		require.NoError(t, err)

		otR1, err := bob.Round5DecommitAndStartOT(aliceProof)
		require.NoError(t, err)

		maskedChoices, err := alice.Round6OTRound2(otR1)
		require.NoError(t, err)

		challenges, err := bob.Round7OTRound3(maskedChoices)
		require.NoError(t, err)

		responses, err := alice.Round8OTRound4(challenges)
		require.NoError(t, err)

		openings, err := bob.Round9OTRound5(responses)
		require.NoError(t, err)

		require.NoError(t, alice.Round10OTRound6(openings))

		aliceOut := alice.Output()
		bobOut := bob.Output()

		// Both parties must agree on the joint public key.
		require.True(t, aliceOut.PublicKey.Equal(bobOut.PublicKey))

		// Verify Q = x_A · x_B · G.
		expectedPK := curve.ScalarBaseMult(aliceOut.SecretKeyShare.Mul(bobOut.SecretKeyShare))
		require.True(t, aliceOut.PublicKey.Equal(expectedPK))
	}
}
