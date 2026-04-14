// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package refresh

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dealer"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/sign"
)

func TestRefreshAndSign(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.P256()} {
		curve := curve
		t.Run(curve.Name, func(t *testing.T) {
			t.Parallel()

			// === DKG via trusted dealer ===
			aliceDkg, bobDkg, err := dealer.GenerateAndDeal(curve)
			require.NoError(t, err)

			// === Key Refresh (3 rounds: Alice sends addend, Bob replies with addend+OTProof, Alice finalizes) ===
			aliceRefresh := NewAlice(curve, aliceDkg)
			bobRefresh := NewBob(curve, bobDkg)

			kA, err := aliceRefresh.Round1AliceAddend()
			require.NoError(t, err)

			r2, err := bobRefresh.Round2BobAddendAndOT(kA)
			require.NoError(t, err)

			require.NoError(t, aliceRefresh.Round3AliceUpdateAndOT(r2))

			newAliceDkg := aliceRefresh.Output()
			newBobDkg := bobRefresh.Output()

			// Public key must be unchanged after refresh.
			require.True(t, newAliceDkg.PublicKey.Equal(aliceDkg.PublicKey))
			require.True(t, newBobDkg.PublicKey.Equal(bobDkg.PublicKey))

			// === Sign with refreshed shares ===
			message := []byte("DKLS19 post-refresh signing test")
			alice := sign.NewAlice(curve, sha3.New256(), newAliceDkg)
			bob := sign.NewBob(curve, sha3.New256(), newBobDkg)

			r1, err := alice.Round1GenerateRandomSeed()
			require.NoError(t, err)

			signR2, err := bob.Round2Initialize(r1)
			require.NoError(t, err)

			signR3, err := alice.Round3Sign(message, signR2)
			require.NoError(t, err)

			require.NoError(t, bob.Round4Final(message, signR3))
			require.NotNil(t, bob.Signature)
		})
	}
}
