// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package dkg implements the Distributed Key Generation (DKG) protocol of
// [DKLS19](https://eprint.iacr.org/2019/523.pdf).
//
// This version replaces the 7-round Simplest OT base setup (Rounds 5-10 in the
// original) with a 2-round Silent OT setup (Rounds 5-6), reducing DKG from 10
// interactive rounds to 6 while cutting per-pair storage from ~24 KB to ~162 bytes.
//
// Round structure:
//
//	Round 1 (Bob→Alice):   Bob's random session seed
//	Round 2 (Alice→Bob):   Alice's seed + Schnorr commitment
//	Round 3 (Bob→Alice):   Bob's Schnorr proof for x_B
//	Round 4 (Alice→Bob):   Alice's Schnorr decommitment for x_A
//	Round 5 (Bob→Alice):   Decommit ACK + Silent OT public key B = b·G + Schnorr proof of b
//	Round 6 (Alice local): Verify OT proof, generate master scalar + choice bits → Output
package dkg

import (
	"crypto/rand"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/silent"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
)

// AliceOutput is the output of the DKG protocol for Alice.
// These values must be stored securely between signing sessions.
type AliceOutput struct {
	// PublicKey is the joint 2-of-2 public key Q = (x_A + x_B)·G.
	PublicKey curves.Point

	// SecretKeyShare is Alice's additive-share of the secret key (x_A).
	SecretKeyShare curves.Scalar

	// SeedOtResult holds the compact silent-OT seed material (replaces the
	// ~8 KB simplest.ReceiverOutput from the previous Simplest OT design).
	SeedOtResult *silent.ReceiverOutput
}

// BobOutput is the output of the DKG protocol for Bob.
type BobOutput struct {
	// PublicKey is the joint 2-of-2 public key Q = (x_A + x_B)·G.
	PublicKey curves.Point

	// SecretKeyShare is Bob's additive-share of the secret key (x_B).
	SecretKeyShare curves.Scalar

	// SeedOtResult holds the compact silent-OT seed material (replaces the
	// ~16 KB simplest.SenderOutput from the previous Simplest OT design).
	SeedOtResult *silent.SenderOutput
}

// Alice holds Alice's mutable state across all rounds of the DKG.
type Alice struct {
	prover         *schnorr.Prover
	proof          *schnorr.Proof
	silentReceiver *silent.ReceiverOutput
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// Bob holds Bob's mutable state across all rounds of the DKG.
type Bob struct {
	prover          *schnorr.Prover
	silentSender    *silent.SenderOutput
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
	Commitment schnorr.Commitment
}

// Round5Output is the message Bob sends to Alice in round 5.
// It bundles the decommitment acknowledgement with the Silent OT key setup.
type Round5Output struct {
	// OTProof is the Schnorr proof of Bob's silent-OT DH secret b.
	OTProof *schnorr.Proof
}

// NewAlice creates a fresh Alice instance ready to begin DKG.
func NewAlice(curve *curves.Curve) *Alice {
	if curve == nil {
		return nil
	}
	return &Alice{
		curve:      curve,
		transcript: merlin.NewTranscript("DKLS19_DKG_v2"),
	}
}

// NewAliceWithSecret creates an Alice instance that uses secretShare as its secret key
// contribution instead of generating a fresh random one. Used in 2-of-n threshold
// setups (Shamir+DKLS19 hybrid).
func NewAliceWithSecret(curve *curves.Curve, secretShare curves.Scalar) *Alice {
	if curve == nil || secretShare == nil {
		return nil
	}
	return &Alice{
		curve:          curve,
		transcript:     merlin.NewTranscript("DKLS19_DKG_v2"),
		secretKeyShare: secretShare,
	}
}

// NewBob creates a fresh Bob instance ready to begin DKG.
func NewBob(curve *curves.Curve) *Bob {
	if curve == nil {
		return nil
	}
	return &Bob{
		curve:      curve,
		transcript: merlin.NewTranscript("DKLS19_DKG_v2"),
	}
}

// NewBobWithSecret creates a Bob instance that uses secretShare as its secret key
// contribution instead of generating a fresh random one.
func NewBobWithSecret(curve *curves.Curve, secretShare curves.Scalar) *Bob {
	if curve == nil || secretShare == nil {
		return nil
	}
	return &Bob{
		curve:          curve,
		transcript:     merlin.NewTranscript("DKLS19_DKG_v2"),
		secretKeyShare: secretShare,
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
func (alice *Alice) Round2CommitToProof(bobSeed [simplest.DigestSize]byte) (*Round2Output, error) {
	aliceSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(aliceSeed[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round2: reading random seed for Alice")
	}
	alice.transcript.AppendMessage([]byte("dkls19_sid_bob"), bobSeed[:])
	alice.transcript.AppendMessage([]byte("dkls19_sid_alice"), aliceSeed[:])

	// Reserve the same label Bob will extract in Round3 so both transcripts stay in sync.
	schnorrID := [simplest.DigestSize]byte{}
	copy(schnorrID[:], alice.transcript.ExtractBytes([]byte("dkls19_schnorr_alice"), simplest.DigestSize))

	if alice.secretKeyShare == nil {
		alice.secretKeyShare = alice.curve.Scalar.Random(rand.Reader)
	}
	alice.prover = schnorr.NewProver(alice.curve, nil, schnorrID[:])

	var err error
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
func (bob *Bob) Round3SchnorrProve(r2 *Round2Output) (*schnorr.Proof, error) {
	bob.transcript.AppendMessage([]byte("dkls19_sid_alice"), r2.Seed[:])
	bob.aliceCommitment = r2.Commitment

	// Store the salt needed to verify Alice's decommitment later.
	copy(bob.aliceSalt[:], bob.transcript.ExtractBytes([]byte("dkls19_schnorr_alice"), simplest.DigestSize))

	schnorrID := [simplest.DigestSize]byte{}
	copy(schnorrID[:], bob.transcript.ExtractBytes([]byte("dkls19_schnorr_bob"), simplest.DigestSize))

	if bob.secretKeyShare == nil {
		bob.secretKeyShare = bob.curve.Scalar.Random(rand.Reader)
	}
	bob.prover = schnorr.NewProver(bob.curve, nil, schnorrID[:])

	proof, err := bob.prover.Prove(bob.secretKeyShare)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round3: Bob Schnorr proof")
	}
	return proof, nil
}

// Round4VerifyAndReveal is Alice's step where she verifies Bob's proof and reveals her own.
func (alice *Alice) Round4VerifyAndReveal(bobProof *schnorr.Proof) (*schnorr.Proof, error) {
	schnorrID := [simplest.DigestSize]byte{}
	copy(schnorrID[:], alice.transcript.ExtractBytes([]byte("dkls19_schnorr_bob"), simplest.DigestSize))

	if err := schnorr.Verify(bobProof, alice.curve, nil, schnorrID[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round4: Alice failed to verify Bob's Schnorr proof")
	}
	alice.publicKey = alice.curve.ScalarBaseMult(alice.secretKeyShare).Add(bobProof.Statement)
	return alice.proof, nil
}

// Round5DecommitAndSendOTKey is Bob's decommitment verification and Silent OT key generation.
// Bob verifies Alice's decommitment, generates the silent-OT DH key pair, and sends
// the public key with a Schnorr proof to Alice.
func (bob *Bob) Round5DecommitAndSendOTKey(aliceProof *schnorr.Proof) (*Round5Output, error) {
	if err := schnorr.DecommitVerify(aliceProof, bob.aliceCommitment, bob.curve, nil, bob.aliceSalt[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round5: Bob failed to verify Alice's decommitment")
	}
	bob.publicKey = aliceProof.Statement.Add(bob.curve.ScalarBaseMult(bob.secretKeyShare))

	// Derive a session-specific ID for the Silent OT Schnorr proof.
	otSessionID := make([]byte, simplest.DigestSize)
	copy(otSessionID, bob.transcript.ExtractBytes([]byte("dkls19_silent_ot"), simplest.DigestSize))

	var err error
	var otProof *schnorr.Proof
	bob.silentSender, otProof, err = silent.NewSender(bob.curve, otSessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 DKG Round5: Silent OT sender setup")
	}
	return &Round5Output{OTProof: otProof}, nil
}

// Round6FinalizeSilentOT is Alice's final DKG step.
// Alice verifies Bob's Silent OT Schnorr proof, then generates her master scalar
// and random choice bits. No message is sent back — Alice's Output() is now ready.
func (alice *Alice) Round6FinalizeSilentOT(r5 *Round5Output) error {
	otSessionID := make([]byte, simplest.DigestSize)
	copy(otSessionID, alice.transcript.ExtractBytes([]byte("dkls19_silent_ot"), simplest.DigestSize))

	recv, err := silent.NewReceiver(alice.curve, r5.OTProof, otSessionID)
	if err != nil {
		return errors.Wrap(err, "DKLS19 DKG Round6: Alice Silent OT finalise")
	}
	alice.silentReceiver = recv
	return nil
}

// Output returns Alice's DKG output after all rounds have completed.
func (alice *Alice) Output() *AliceOutput {
	if alice.silentReceiver == nil || alice.publicKey == nil {
		return nil
	}
	return &AliceOutput{
		PublicKey:      alice.publicKey,
		SecretKeyShare: alice.secretKeyShare,
		SeedOtResult:   alice.silentReceiver,
	}
}

// Output returns Bob's DKG output after all rounds have completed.
func (bob *Bob) Output() *BobOutput {
	if bob.silentSender == nil {
		return nil
	}
	return &BobOutput{
		PublicKey:      bob.publicKey,
		SecretKeyShare: bob.secretKeyShare,
		SeedOtResult:   bob.silentSender,
	}
}
