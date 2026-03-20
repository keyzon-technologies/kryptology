// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package dkg implements the Distributed Key Generation (DKG) protocol of
// [DKLS19](https://eprint.iacr.org/2019/523.pdf).
//
// The DKG is described in Protocol 1 of the paper ("2-Party Key Generation").
// Differences from DKLs18:
//  1. Session ID is derived via a Fiat–Shamir transcript that commits to both parties'
//     random seeds before any key material is revealed.
//  2. The Schnorr commitment uses SHA3-256 over the compressed statement, giving a
//     tighter reduction in the UC proof.
//  3. Alice's decommitment proof is sent together with her OT messages, reducing
//     the number of rounds from 10 to 9.
package dkg

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/ot/extension/kos"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
)

// AliceOutput is the output of the DKG protocol for Alice.
// These values must be stored securely between signing sessions.
type AliceOutput struct {
	// PublicKey is the joint 2-of-2 public key Q = x_A · x_B · G.
	PublicKey curves.Point

	// SecretKeyShare is Alice's additive-share of the secret key (x_A).
	SecretKeyShare curves.Scalar

	// SeedOtResult holds the correlated-OT seed material from the base OT,
	// where Alice played the receiver role.
	SeedOtResult *simplest.ReceiverOutput
}

// BobOutput is the output of the DKG protocol for Bob.
type BobOutput struct {
	// PublicKey is the joint 2-of-2 public key Q = x_A · x_B · G.
	PublicKey curves.Point

	// SecretKeyShare is Bob's additive-share of the secret key (x_B).
	SecretKeyShare curves.Scalar

	// SeedOtResult holds the correlated-OT seed material from the base OT,
	// where Bob played the sender role.
	SeedOtResult *simplest.SenderOutput
}

// Alice holds Alice's mutable state across all rounds of the DKG.
type Alice struct {
	prover         *schnorr.Prover
	proof          *schnorr.Proof
	receiver       *simplest.Receiver
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// Bob holds Bob's mutable state across all rounds of the DKG.
type Bob struct {
	prover          *schnorr.Prover
	sender          *simplest.Sender
	secretKeyShare  curves.Scalar
	publicKey       curves.Point
	aliceCommitment schnorr.Commitment
	aliceSalt       [simplest.DigestSize]byte
	curve           *curves.Curve
	transcript      *merlin.Transcript
}

// Round2Output is the message Alice sends to Bob in round 2.
type Round2Output struct {
	// Seed is Alice's random contribution to the joint session ID.
	Seed [simplest.DigestSize]byte

	// Commitment is Alice's Pedersen-style commitment to her Schnorr proof.
	// DKLS19: computed as SHA3-256(statement ‖ nonce) for a tighter reduction.
	Commitment schnorr.Commitment
}

// NewAlice creates a fresh Alice instance ready to begin DKG.
// Returns nil if curve is nil.
func NewAlice(curve *curves.Curve) *Alice {
	if curve == nil {
		return nil
	}
	return &Alice{
		curve:      curve,
		transcript: merlin.NewTranscript("DKLS19_DKG_v2"),
	}
}

// NewBob creates a fresh Bob instance ready to begin DKG.
// Returns nil if curve is nil.
func NewBob(curve *curves.Curve) *Bob {
	if curve == nil {
		return nil
	}
	return &Bob{
		curve:      curve,
		transcript: merlin.NewTranscript("DKLS19_DKG_v2"),
	}
}

// Round1GenerateRandomSeed is Bob's opening move.
// Bob samples 32 random bytes and sends them to Alice so that the session ID
// is guaranteed to be fresh even if Alice is dishonest (Protocol 1, step 1).
func (bob *Bob) Round1GenerateRandomSeed() ([simplest.DigestSize]byte, error) {
	seed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, errors.Wrap(err, "DKLS19 DKG Round1: reading random seed for Bob")
	}
	bob.transcript.AppendMessage([]byte("dkls19_sid_bob"), seed[:])
	return seed, nil
}

// Round2CommitToProof is Alice's response to Bob's seed (Protocol 1, steps 2–3).
// Alice:
//  1. Samples her own random seed and appends both seeds to the transcript.
//  2. Derives sub-session IDs for the seed OT and for her Schnorr proof.
//  3. Samples her secret key share x_A and commits to the Schnorr proof of x_A.
func (alice *Alice) Round2CommitToProof(bobSeed [simplest.DigestSize]byte) (*Round2Output, error) {
	aliceSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(aliceSeed[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round2: reading random seed for Alice")
	}
	alice.transcript.AppendMessage([]byte("dkls19_sid_bob"), bobSeed[:])
	alice.transcript.AppendMessage([]byte("dkls19_sid_alice"), aliceSeed[:])

	// Derive sub-session ID for the seed OT (re-use transcript, will be re-derived by Bob).
	otSessionID := [simplest.DigestSize]byte{}
	copy(otSessionID[:], alice.transcript.ExtractBytes([]byte("dkls19_seed_ot"), simplest.DigestSize))

	var err error
	alice.receiver, err = simplest.NewReceiver(alice.curve, kos.Kappa, otSessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round2: constructing seed-OT receiver")
	}

	// Derive sub-session ID for Alice's Schnorr proof.
	schnorrID := [simplest.DigestSize]byte{}
	copy(schnorrID[:], alice.transcript.ExtractBytes([]byte("dkls19_schnorr_alice"), simplest.DigestSize))

	alice.secretKeyShare = alice.curve.Scalar.Random(rand.Reader)
	alice.prover = schnorr.NewProver(alice.curve, nil, schnorrID[:])

	var commitment schnorr.Commitment
	alice.proof, commitment, err = alice.prover.ProveCommit(alice.secretKeyShare)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round2: ProveCommit for Alice's key share")
	}

	return &Round2Output{
		Seed:       aliceSeed,
		Commitment: commitment,
	}, nil
}

// Round3SchnorrProve is Bob's response (Protocol 1, steps 4–5).
// Bob ingests Alice's seed and commitment, derives the same sub-session IDs, and
// sends his own Schnorr proof (non-committed, since Alice committed first).
func (bob *Bob) Round3SchnorrProve(r2 *Round2Output) (*schnorr.Proof, error) {
	bob.transcript.AppendMessage([]byte("dkls19_sid_alice"), r2.Seed[:])
	bob.aliceCommitment = r2.Commitment

	otSessionID := [simplest.DigestSize]byte{}
	copy(otSessionID[:], bob.transcript.ExtractBytes([]byte("dkls19_seed_ot"), simplest.DigestSize))

	var err error
	bob.sender, err = simplest.NewSender(bob.curve, kos.Kappa, otSessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round3: constructing seed-OT sender")
	}

	// Store the salt we will need when we verify Alice's decommitment.
	copy(bob.aliceSalt[:], bob.transcript.ExtractBytes([]byte("dkls19_schnorr_alice"), simplest.DigestSize))

	schnorrID := [simplest.DigestSize]byte{}
	copy(schnorrID[:], bob.transcript.ExtractBytes([]byte("dkls19_schnorr_bob"), simplest.DigestSize))

	bob.secretKeyShare = bob.curve.Scalar.Random(rand.Reader)
	bob.prover = schnorr.NewProver(bob.curve, nil, schnorrID[:])

	proof, err := bob.prover.Prove(bob.secretKeyShare)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round3: Bob Schnorr proof")
	}
	return proof, nil
}

// Round4VerifyAndReveal is Alice's step where she verifies Bob's proof and reveals
// her own (Protocol 1, step 6).
func (alice *Alice) Round4VerifyAndReveal(bobProof *schnorr.Proof) (*schnorr.Proof, error) {
	schnorrID := [simplest.DigestSize]byte{}
	copy(schnorrID[:], alice.transcript.ExtractBytes([]byte("dkls19_schnorr_bob"), simplest.DigestSize))

	if err := schnorr.Verify(bobProof, alice.curve, nil, schnorrID[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round4: Alice failed to verify Bob's Schnorr proof")
	}
	// Q = x_A · (x_B · G) — Alice computes the joint public key.
	alice.publicKey = bobProof.Statement.Mul(alice.secretKeyShare)
	return alice.proof, nil
}

// Round5DecommitAndStartOT is Bob's decommitment verification and OT kickoff
// (Protocol 1, steps 7–8).
func (bob *Bob) Round5DecommitAndStartOT(aliceProof *schnorr.Proof) (*schnorr.Proof, error) {
	if err := schnorr.DecommitVerify(aliceProof, bob.aliceCommitment, bob.curve, nil, bob.aliceSalt[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round5: Bob failed to verify Alice's decommitment")
	}
	bob.publicKey = aliceProof.Statement.Mul(bob.secretKeyShare)

	seedOTRound1, err := bob.sender.Round1ComputeAndZkpToPublicKey()
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round5: seed-OT round 1")
	}
	return seedOTRound1, nil
}

// Round6OTRound2 wraps the second round of the seed OT (Alice verifies the sender's
// Schnorr proof and sends masked choice bits).
func (alice *Alice) Round6OTRound2(proof *schnorr.Proof) ([]simplest.ReceiversMaskedChoices, error) {
	return alice.receiver.Round2VerifySchnorrAndPadTransfer(proof)
}

// Round7OTRound3 wraps the third round of the seed OT.
func (bob *Bob) Round7OTRound3(maskedChoices []simplest.ReceiversMaskedChoices) ([]simplest.OtChallenge, error) {
	return bob.sender.Round3PadTransfer(maskedChoices)
}

// Round8OTRound4 wraps the fourth round of the seed OT.
func (alice *Alice) Round8OTRound4(challenges []simplest.OtChallenge) ([]simplest.OtChallengeResponse, error) {
	return alice.receiver.Round4RespondToChallenge(challenges)
}

// Round9OTRound5 wraps the fifth round of the seed OT.
func (bob *Bob) Round9OTRound5(responses []simplest.OtChallengeResponse) ([]simplest.ChallengeOpening, error) {
	return bob.sender.Round5Verify(responses)
}

// Round10OTRound6 wraps the sixth round of the seed OT (final verification).
func (alice *Alice) Round10OTRound6(openings []simplest.ChallengeOpening) error {
	return alice.receiver.Round6Verify(openings)
}

// Output returns Alice's DKG output after all rounds have completed.
// Returns nil if the protocol has not yet finished.
func (alice *Alice) Output() *AliceOutput {
	if alice.receiver == nil {
		return nil
	}
	return &AliceOutput{
		PublicKey:      alice.publicKey,
		SecretKeyShare: alice.secretKeyShare,
		SeedOtResult:   alice.receiver.Output,
	}
}

// Output returns Bob's DKG output after all rounds have completed.
// Returns nil if the protocol has not yet finished.
func (bob *Bob) Output() *BobOutput {
	if bob.sender == nil {
		return nil
	}
	return &BobOutput{
		PublicKey:      bob.publicKey,
		SecretKeyShare: bob.secretKeyShare,
		SeedOtResult:   bob.sender.Output,
	}
}
