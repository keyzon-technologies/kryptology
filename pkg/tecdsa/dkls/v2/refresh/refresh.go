// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package refresh implements the key-share refresh protocol for DKLS19.
//
// The refresh protocol lets Alice and Bob rotate their additive key shares
// and re-seed the correlated OT material without changing the joint public key.
//
// Protocol outline (mirrors DKLs18 refresh with updated transcript labels):
//  1. Alice samples k_A ← F_q, writes it to the transcript, and sends it to Bob.
//  2. Bob receives k_A, samples k_B ← F_q, writes both to the transcript, reads
//     the common multiplier k = Transcript("refresh_multiplier"), and updates:
//     sk_B ← sk_B · k.  Sends k_B to Alice.
//  3. Alice writes k_B, reads k, and updates: sk_A ← sk_A · k^{−1}.
//  4. Both parties redo the seed OT (identical to the DKG seed OT phase).
//
// Invariant: sk_A' · sk_B' = (sk_A · k^{−1}) · (sk_B · k) = sk_A · sk_B,
// so the joint public key Q = sk_A · sk_B · G is unchanged.
package refresh

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/ot/extension/kos"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
)

// Alice holds Alice's mutable state during one refresh execution.
type Alice struct {
	receiver       *simplest.Receiver
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// Bob holds Bob's mutable state during one refresh execution.
type Bob struct {
	sender         *simplest.Sender
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// RefreshRound2Output is Bob's first message to Alice in the refresh protocol.
type RefreshRound2Output struct {
	// SeedOTRound1Output is the Schnorr proof from the sender side of the new seed OT.
	SeedOTRound1Output *schnorr.Proof

	// BobMultiplier is k_B, Bob's random contribution to the refresh.
	BobMultiplier curves.Scalar
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

// Round1AliceMultiplier is Alice's opening move.
// She samples k_A ← F_q, appends it to the transcript, and sends it to Bob.
func (alice *Alice) Round1AliceMultiplier() (curves.Scalar, error) {
	kA := alice.curve.Scalar.Random(rand.Reader)
	alice.transcript.AppendMessage([]byte("dkls19_refresh_kA"), kA.Bytes())
	return kA, nil
}

// Round2BobMultiplierAndOT is Bob's response.
// Bob appends k_A, samples k_B, derives the common multiplier k, updates his
// key share, and kicks off the new seed OT.
func (bob *Bob) Round2BobMultiplierAndOT(kA curves.Scalar) (*RefreshRound2Output, error) {
	bob.transcript.AppendMessage([]byte("dkls19_refresh_kA"), kA.Bytes())

	kB := bob.curve.Scalar.Random(rand.Reader)
	bob.transcript.AppendMessage([]byte("dkls19_refresh_kB"), kB.Bytes())

	// Derive the common multiplier k from the transcript.
	kBytes := bob.transcript.ExtractBytes([]byte("dkls19_refresh_multiplier"), simplest.DigestSize)
	k, err := bob.curve.Scalar.SetBytes(kBytes)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round2: derive k")
	}

	if k.IsZero() {
		return nil, errors.New("DKLS19 refresh Round2: derived multiplier k is zero")
	}
	// sk_B ← sk_B · k
	bob.secretKeyShare = bob.secretKeyShare.Mul(k)

	// Initialise new seed OT with a fresh session ID.
	otSessionID := [simplest.DigestSize]byte{}
	copy(otSessionID[:], bob.transcript.ExtractBytes([]byte("dkls19_refresh_ot_sid"), simplest.DigestSize))

	bob.sender, err = simplest.NewSender(bob.curve, kos.Kappa, otSessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round2: new OT sender")
	}
	otR1, err := bob.sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round2: OT Round1")
	}
	return &RefreshRound2Output{
		SeedOTRound1Output: otR1,
		BobMultiplier:      kB,
	}, nil
}

// Round3AliceUpdateAndOT is Alice's reply.
// She appends k_B, derives k, updates her key share as sk_A ← sk_A · k^{−1},
// and advances the seed OT.
func (alice *Alice) Round3AliceUpdateAndOT(r2 *RefreshRound2Output) ([]simplest.ReceiversMaskedChoices, error) {
	alice.transcript.AppendMessage([]byte("dkls19_refresh_kB"), r2.BobMultiplier.Bytes())

	kBytes := alice.transcript.ExtractBytes([]byte("dkls19_refresh_multiplier"), simplest.DigestSize)
	k, err := alice.curve.Scalar.SetBytes(kBytes)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round3: derive k")
	}

	if k.IsZero() {
		return nil, errors.New("DKLS19 refresh Round3: derived multiplier k is zero")
	}
	// sk_A ← sk_A · k^{−1}  so that sk_A' · sk_B' = sk_A · sk_B.
	alice.secretKeyShare = alice.secretKeyShare.Mul(alice.curve.Scalar.One().Div(k))

	otSessionID := [simplest.DigestSize]byte{}
	copy(otSessionID[:], alice.transcript.ExtractBytes([]byte("dkls19_refresh_ot_sid"), simplest.DigestSize))

	alice.receiver, err = simplest.NewReceiver(alice.curve, kos.Kappa, otSessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 refresh Round3: new OT receiver")
	}
	return alice.receiver.Round2VerifySchnorrAndPadTransfer(r2.SeedOTRound1Output)
}

// Round4OTRound3 wraps the third round of the seed OT.
func (bob *Bob) Round4OTRound3(maskedChoices []simplest.ReceiversMaskedChoices) ([]simplest.OtChallenge, error) {
	return bob.sender.Round3PadTransfer(maskedChoices)
}

// Round5OTRound4 wraps the fourth round of the seed OT.
func (alice *Alice) Round5OTRound4(challenges []simplest.OtChallenge) ([]simplest.OtChallengeResponse, error) {
	return alice.receiver.Round4RespondToChallenge(challenges)
}

// Round6OTRound5 wraps the fifth round of the seed OT.
func (bob *Bob) Round6OTRound5(responses []simplest.OtChallengeResponse) ([]simplest.ChallengeOpening, error) {
	return bob.sender.Round5Verify(responses)
}

// Round7OTRound6 wraps the sixth (final) round of the seed OT.
func (alice *Alice) Round7OTRound6(openings []simplest.ChallengeOpening) error {
	return alice.receiver.Round6Verify(openings)
}

// Output returns Alice's refreshed DKG output.
// Returns nil if the refresh protocol has not yet finished.
func (alice *Alice) Output() *dkg.AliceOutput {
	if alice.receiver == nil {
		return nil
	}
	return &dkg.AliceOutput{
		PublicKey:      alice.publicKey,
		SecretKeyShare: alice.secretKeyShare,
		SeedOtResult:   alice.receiver.Output,
	}
}

// Output returns Bob's refreshed DKG output.
// Returns nil if the refresh protocol has not yet finished.
func (bob *Bob) Output() *dkg.BobOutput {
	if bob.sender == nil {
		return nil
	}
	return &dkg.BobOutput{
		PublicKey:      bob.publicKey,
		SecretKeyShare: bob.secretKeyShare,
		SeedOtResult:   bob.sender.Output,
	}
}
