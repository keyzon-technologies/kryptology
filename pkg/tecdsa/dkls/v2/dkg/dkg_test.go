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

		r5, err := bob.Round5DecommitAndSendOTKey(aliceProof)
		require.NoError(t, err)

		require.NoError(t, alice.Round6FinalizeSilentOT(r5))

		aliceOut := alice.Output()
		bobOut := bob.Output()

		// Both parties must agree on the joint public key.
		require.True(t, aliceOut.PublicKey.Equal(bobOut.PublicKey))

		// Verify Q = (x_A + x_B)·G.
		expectedPK := curve.ScalarBaseMult(aliceOut.SecretKeyShare).Add(curve.ScalarBaseMult(bobOut.SecretKeyShare))
		require.True(t, aliceOut.PublicKey.Equal(expectedPK))
	}
}
