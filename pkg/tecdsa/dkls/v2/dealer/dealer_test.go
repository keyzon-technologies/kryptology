// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package dealer

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
)

func TestGenerateAndDeal(t *testing.T) {
	t.Parallel()
	for _, curve := range []*curves.Curve{curves.K256(), curves.P256()} {
		curve := curve
		t.Run(curve.Name, func(t *testing.T) {
			t.Parallel()
			alice, bob, err := GenerateAndDeal(curve)
			require.NoError(t, err)

			// Both parties must agree on the public key.
			require.True(t, alice.PublicKey.Equal(bob.PublicKey))

			// Q == x_A · x_B · G
			expected := curve.ScalarBaseMult(alice.SecretKeyShare.Mul(bob.SecretKeyShare))
			require.True(t, alice.PublicKey.Equal(expected))

			require.NotNil(t, alice.SeedOtResult)
			require.NotNil(t, bob.SeedOtResult)
		})
	}
}
