// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package refresh implements the key-share refresh protocol for DKLS19.
//
// The refresh protocol lets Alice and Bob rotate their additive key shares
// and re-seed the correlated OT material without changing the joint public key.
//
// Protocol outline (additive refresh, Silent OT variant):
//  1. Alice samples k_A ← F_q, writes it to the transcript, and sends it to Bob.
//  2. Bob appends k_A, samples k_B, derives the common addend k, updates
//     sk_B ← sk_B + k.  Generates new silent-OT DH key + Schnorr proof.  Sends k_B + OTProof.
//  3. Alice appends k_B, derives k, updates sk_A ← sk_A − k, verifies OTProof,
//     and stores her new ReceiverOutput.  No further rounds.
//
// Invariant: sk_A' + sk_B' = (sk_A − k) + (sk_B + k) = sk_A + sk_B = x,
// so the joint public key Q = (sk_A + sk_B)·G is unchanged.
package refresh

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/silent"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
)

// Alice holds Alice's mutable state during one refresh execution.
type Alice struct {
	silentReceiver *silent.ReceiverOutput
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// Bob holds Bob's mutable state during one refresh execution.
type Bob struct {
	silentSender   *silent.SenderOutput
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// RefreshRound2Output is Bob's message to Alice in the refresh protocol.
type RefreshRound2Output struct {
	// OTProof is the Schnorr proof of Bob's silent-OT DH secret b.
	OTProof *schnorr.Proof

	// BobAddend is k_B, Bob's random contribution to the refresh transcript.
	BobAddend curves.Scalar
}

// NewAlice creates an Alice refresh instance from existing DKG output.
// Returns nil if curve or dkgOutput is nil.
func NewAlice(curve *curves.Curve, dkgOutput *dkg.AliceOutput) *Alice {
	if curve == nil || dkgOutput == nil {
		return nil
	}
	return &Alice{
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("DKLS19_Refresh_v2"),
	}
}

// NewBob creates a Bob refresh instance from existing DKG output.
// Returns nil if curve or dkgOutput is nil.
func NewBob(curve *curves.Curve, dkgOutput *dkg.BobOutput) *Bob {
	if curve == nil || dkgOutput == nil {
		return nil
	}
	return &Bob{
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("DKLS19_Refresh_v2"),
	}
}

// Round1AliceAddend is Alice's opening move.
// She samples k_A ← F_q, appends it to the transcript, and sends it to Bob.
func (alice *Alice) Round1AliceAddend() (curves.Scalar, error) {
	kA := alice.curve.Scalar.Random(rand.Reader)
	alice.transcript.AppendMessage([]byte("dkls19_refresh_kA"), kA.Bytes())
	return kA, nil
}

// Round2BobAddendAndOT is Bob's response.
// Bob appends k_A, samples k_B, derives the common addend k, updates his
// key share as sk_B ← sk_B + k, and generates the new silent-OT DH key pair.
func (bob *Bob) Round2BobAddendAndOT(kA curves.Scalar) (*RefreshRound2Output, error) {
	bob.transcript.AppendMessage([]byte("dkls19_refresh_kA"), kA.Bytes())

	kB := bob.curve.Scalar.Random(rand.Reader)
	bob.transcript.AppendMessage([]byte("dkls19_refresh_kB"), kB.Bytes())

	// Derive the common addend k from the transcript.
	kBytes := bob.transcript.ExtractBytes([]byte("dkls19_refresh_addend"), simplest.DigestSize)
	k, err := bob.curve.Scalar.SetBytes(kBytes)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round2: derive k")
	}

	// sk_B ← sk_B + k
	bob.secretKeyShare = bob.secretKeyShare.Add(k)

	// Derive a session-specific ID for the Silent OT Schnorr proof.
	otSessionID := make([]byte, simplest.DigestSize)
	copy(otSessionID, bob.transcript.ExtractBytes([]byte("dkls19_refresh_silent_ot"), simplest.DigestSize))

	var otProof *schnorr.Proof
	bob.silentSender, otProof, err = silent.NewSender(bob.curve, otSessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round2: Silent OT sender setup")
	}
	return &RefreshRound2Output{OTProof: otProof, BobAddend: kB}, nil
}

// Round3AliceUpdateAndOT is Alice's final step.
// She appends k_B, derives k, updates her key share as sk_A ← sk_A − k,
// verifies Bob's Silent OT Schnorr proof, and stores her new ReceiverOutput.
func (alice *Alice) Round3AliceUpdateAndOT(r2 *RefreshRound2Output) error {
	alice.transcript.AppendMessage([]byte("dkls19_refresh_kB"), r2.BobAddend.Bytes())

	kBytes := alice.transcript.ExtractBytes([]byte("dkls19_refresh_addend"), simplest.DigestSize)
	k, err := alice.curve.Scalar.SetBytes(kBytes)
	if err != nil {
		return errors.Wrap(err, "DKLS19 refresh Round3: derive k")
	}

	// sk_A ← sk_A − k  so that sk_A' + sk_B' = sk_A + sk_B = x.
	alice.secretKeyShare = alice.secretKeyShare.Sub(k)

	otSessionID := make([]byte, simplest.DigestSize)
	copy(otSessionID, alice.transcript.ExtractBytes([]byte("dkls19_refresh_silent_ot"), simplest.DigestSize))

	alice.silentReceiver, err = silent.NewReceiver(alice.curve, r2.OTProof, otSessionID)
	if err != nil {
		return errors.Wrap(err, "DKLS19 refresh Round3: Silent OT receiver setup")
	}
	return nil
}

// Output returns Alice's refreshed DKG output.
// Returns nil if the refresh protocol has not yet finished.
func (alice *Alice) Output() *dkg.AliceOutput {
	if alice.silentReceiver == nil {
		return nil
	}
	return &dkg.AliceOutput{
		PublicKey:      alice.publicKey,
		SecretKeyShare: alice.secretKeyShare,
		SeedOtResult:   alice.silentReceiver,
	}
}

// Output returns Bob's refreshed DKG output.
// Returns nil if the refresh protocol has not yet finished.
func (bob *Bob) Output() *dkg.BobOutput {
	if bob.silentSender == nil {
		return nil
	}
	return &dkg.BobOutput{
		PublicKey:      bob.publicKey,
		SecretKeyShare: bob.secretKeyShare,
		SeedOtResult:   bob.silentSender,
	}
}
