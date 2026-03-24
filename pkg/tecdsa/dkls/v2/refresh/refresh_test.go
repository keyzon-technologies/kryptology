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

			// === Key Refresh ===
			aliceRefresh := NewAlice(curve, aliceDkg)
			bobRefresh := NewBob(curve, bobDkg)

			kA, err := aliceRefresh.Round1AliceAddend()
			require.NoError(t, err)

			r2, err := bobRefresh.Round2BobAddendAndOT(kA)
			require.NoError(t, err)

			maskedChoices, err := aliceRefresh.Round3AliceUpdateAndOT(r2)
			require.NoError(t, err)

			challenges, err := bobRefresh.Round4OTRound3(maskedChoices)
			require.NoError(t, err)

			responses, err := aliceRefresh.Round5OTRound4(challenges)
			require.NoError(t, err)

			openings, err := bobRefresh.Round6OTRound5(responses)
			require.NoError(t, err)

			require.NoError(t, aliceRefresh.Round7OTRound6(openings))

			newAliceDkg := aliceRefresh.Output()
			newBobDkg := bobRefresh.Output()

			// Public key must be unchanged after refresh.
			require.True(t, newAliceDkg.PublicKey.Equal(aliceDkg.PublicKey))
			require.True(t, newBobDkg.PublicKey.Equal(bobDkg.PublicKey))

			// === Sign with refreshed shares ===
			message := []byte("DKLS19 post-refresh signing test")
			alice := sign.NewAlice(curve, sha3.New256(), newAliceDkg)
			bob := sign.NewBob(curve, sha3.New256(), newBobDkg)

			aliceSeed, err := alice.Round1GenerateRandomSeed()
			require.NoError(t, err)

			signR2, err := bob.Round2Initialize(aliceSeed)
			require.NoError(t, err)

			signR3, err := alice.Round3Sign(message, signR2)
			require.NoError(t, err)

			require.NoError(t, bob.Round4Final(message, signR3))
			require.NotNil(t, bob.Signature)
		})
	}
}
