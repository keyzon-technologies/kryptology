// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v2

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/sha3"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
)

// doDKG runs the full 10-round DKLS19 DKG via the protocol.Iterator interface
// and returns the serialised DKG result messages for Alice and Bob.
func doDKG(t *testing.T, curve *curves.Curve) (aliceResult, bobResult *protocol.Message) {
	t.Helper()

	aliceDkg := NewAliceDkg(curve, Version2)
	bobDkg := NewBobDkg(curve, Version2)

	// Bob initiates (no input needed for round 1).
	msg, err := bobDkg.Next(nil)
	require.NoError(t, err)

	// Alice → commits to proof.
	msg, err = aliceDkg.Next(msg)
	require.NoError(t, err)

	// Bob → proves key share.
	msg, err = bobDkg.Next(msg)
	require.NoError(t, err)

	// Alice → verify Bob's proof, reveal her own.
	msg, err = aliceDkg.Next(msg)
	require.NoError(t, err)

	// Bob → decommit + start OT.
	msg, err = bobDkg.Next(msg)
	require.NoError(t, err)

	// Alice → OT Round 2.
	msg, err = aliceDkg.Next(msg)
	require.NoError(t, err)

	// Bob → OT Round 3.
	msg, err = bobDkg.Next(msg)
	require.NoError(t, err)

	// Alice → OT Round 4.
	msg, err = aliceDkg.Next(msg)
	require.NoError(t, err)

	// Bob → OT Round 5 (last Bob step).
	msg, err = bobDkg.Next(msg)
	require.NoError(t, err)

	// Alice → OT Round 6 (last Alice step, no reply).
	_, err = aliceDkg.Next(msg)
	require.NoError(t, err)

	aliceResult, err = aliceDkg.Result(Version2)
	require.NoError(t, err)
	require.NotNil(t, aliceResult)

	bobResult, err = bobDkg.Result(Version2)
	require.NoError(t, err)
	require.NotNil(t, bobResult)

	return aliceResult, bobResult
}

// ── DKG tests ─────────────────────────────────────────────────────────────────

func TestProtocolDKGFull_K256(t *testing.T) {
	t.Parallel()
	testProtocolDKG(t, curves.K256())
}

func TestProtocolDKGFull_P256(t *testing.T) {
	t.Parallel()
	testProtocolDKG(t, curves.P256())
}

func testProtocolDKG(t *testing.T, curve *curves.Curve) {
	t.Helper()
	aliceResult, bobResult := doDKG(t, curve)

	aliceOut, err := DecodeAliceDkgResult(aliceResult)
	require.NoError(t, err)
	bobOut, err := DecodeBobDkgResult(bobResult)
	require.NoError(t, err)

	// Both parties must agree on the joint public key.
	require.True(t, aliceOut.PublicKey.Equal(bobOut.PublicKey))

	// Q = (x_A + x_B)·G.
	expected := curve.ScalarBaseMult(aliceOut.SecretKeyShare).Add(curve.ScalarBaseMult(bobOut.SecretKeyShare))
	require.True(t, aliceOut.PublicKey.Equal(expected))
}

// ── Sign tests ────────────────────────────────────────────────────────────────

func TestProtocolSignFull_K256(t *testing.T) {
	t.Parallel()
	testProtocolSign(t, curves.K256())
}

func TestProtocolSignFull_P256(t *testing.T) {
	t.Parallel()
	testProtocolSign(t, curves.P256())
}

func testProtocolSign(t *testing.T, curve *curves.Curve) {
	t.Helper()
	aliceResult, bobResult := doDKG(t, curve)

	message := []byte("DKLS19 v2 integration test message")

	aliceSign, err := NewAliceSign(curve, sha3.New256(), message, aliceResult, Version2)
	require.NoError(t, err)
	bobSign, err := NewBobSign(curve, sha3.New256(), message, bobResult, Version2)
	require.NoError(t, err)

	// Alice sends seed.
	msg, err := aliceSign.Next(nil)
	require.NoError(t, err)

	// Bob initialises and replies.
	msg, err = bobSign.Next(msg)
	require.NoError(t, err)

	// Alice produces her signing message.
	msg, err = aliceSign.Next(msg)
	require.NoError(t, err)

	// Bob finalises the signature.
	_, err = bobSign.Next(msg)
	require.NoError(t, err)

	sigMsg, err := bobSign.Result(Version2)
	require.NoError(t, err)
	require.NotNil(t, sigMsg)

	// Verify the signature externally using the standard crypto/ecdsa package.
	aliceOut, err := DecodeAliceDkgResult(aliceResult)
	require.NoError(t, err)

	uncompressed := aliceOut.PublicKey.ToAffineUncompressed()
	require.Len(t, uncompressed, 65)
	x := new(big.Int).SetBytes(uncompressed[1:33])
	y := new(big.Int).SetBytes(uncompressed[33:])
	ellipticCurve, err := curve.ToEllipticCurve()
	require.NoError(t, err)
	pubKey := &ecdsa.PublicKey{Curve: ellipticCurve, X: x, Y: y}

	h := sha3.New256()
	_, err = h.Write(message)
	require.NoError(t, err)
	digest := h.Sum(nil)

	sig, err := DecodeSignature(sigMsg)
	require.NoError(t, err)
	require.True(t, ecdsa.Verify(pubKey, digest, sig.R, sig.S),
		"ECDSA signature must verify against the joint public key")
}

// ── Refresh tests ─────────────────────────────────────────────────────────────

func TestProtocolRefreshAndSign(t *testing.T) {
	t.Parallel()
	curve := curves.K256()

	aliceResult, bobResult := doDKG(t, curve)

	alicePreRefresh, err := DecodeAliceDkgResult(aliceResult)
	require.NoError(t, err)

	// ── Key Refresh ───────────────────────────────────────────────────────────
	aliceRefresh, err := NewAliceRefresh(curve, aliceResult, Version2)
	require.NoError(t, err)
	bobRefresh, err := NewBobRefresh(curve, bobResult, Version2)
	require.NoError(t, err)

	// Alice sends k_A.
	msg, err := aliceRefresh.Next(nil)
	require.NoError(t, err)

	// Bob updates his share and starts OT.
	msg, err = bobRefresh.Next(msg)
	require.NoError(t, err)

	// Alice updates her share and runs OT Round2.
	msg, err = aliceRefresh.Next(msg)
	require.NoError(t, err)

	// Bob → OT Round3.
	msg, err = bobRefresh.Next(msg)
	require.NoError(t, err)

	// Alice → OT Round4.
	msg, err = aliceRefresh.Next(msg)
	require.NoError(t, err)

	// Bob → OT Round5.
	msg, err = bobRefresh.Next(msg)
	require.NoError(t, err)

	// Alice → OT Round6 (final).
	_, err = aliceRefresh.Next(msg)
	require.NoError(t, err)

	newAliceResult, err := aliceRefresh.Result(Version2)
	require.NoError(t, err)
	newBobResult, err := bobRefresh.Result(Version2)
	require.NoError(t, err)

	// The joint public key must be unchanged after refresh.
	newAlice, err := DecodeAliceDkgResult(newAliceResult)
	require.NoError(t, err)
	require.True(t, alicePreRefresh.PublicKey.Equal(newAlice.PublicKey),
		"public key must not change after key refresh")

	// ── Sign with refreshed shares ────────────────────────────────────────────
	message := []byte("DKLS19 post-refresh signing")

	aliceSign, err := NewAliceSign(curve, sha3.New256(), message, newAliceResult, Version2)
	require.NoError(t, err)
	bobSign, err := NewBobSign(curve, sha3.New256(), message, newBobResult, Version2)
	require.NoError(t, err)

	msg, err = aliceSign.Next(nil)
	require.NoError(t, err)
	msg, err = bobSign.Next(msg)
	require.NoError(t, err)
	msg, err = aliceSign.Next(msg)
	require.NoError(t, err)
	_, err = bobSign.Next(msg)
	require.NoError(t, err)

	sigMsg, err := bobSign.Result(Version2)
	require.NoError(t, err)
	require.NotNil(t, sigMsg)
}
