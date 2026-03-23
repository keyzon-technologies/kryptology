// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v2

import (
	"hash"

	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/refresh"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/sign"
)

// ── DKG types ────────────────────────────────────────────────────────────────

// AliceDkg wraps dkg.Alice and satisfies protocol.Iterator.
type AliceDkg struct {
	protoStepper
	*dkg.Alice
}

// BobDkg wraps dkg.Bob and satisfies protocol.Iterator.
type BobDkg struct {
	protoStepper
	*dkg.Bob
}

// ── Sign types ────────────────────────────────────────────────────────────────

// AliceSign wraps sign.Alice and satisfies protocol.Iterator.
type AliceSign struct {
	protoStepper
	*sign.Alice
}

// BobSign wraps sign.Bob and satisfies protocol.Iterator.
type BobSign struct {
	protoStepper
	*sign.Bob
}

// ── Refresh types ─────────────────────────────────────────────────────────────

// AliceRefresh wraps refresh.Alice and satisfies protocol.Iterator.
type AliceRefresh struct {
	protoStepper
	*refresh.Alice
}

// BobRefresh wraps refresh.Bob and satisfies protocol.Iterator.
type BobRefresh struct {
	protoStepper
	*refresh.Bob
}

// ── Static interface assertions ───────────────────────────────────────────────

var (
	_ protocol.Iterator = &AliceDkg{}
	_ protocol.Iterator = &BobDkg{}
	_ protocol.Iterator = &AliceSign{}
	_ protocol.Iterator = &BobSign{}
	_ protocol.Iterator = &AliceRefresh{}
	_ protocol.Iterator = &BobRefresh{}
)

// ── DKG constructors ──────────────────────────────────────────────────────────

// newAliceDkgFromAlice is the shared constructor logic for AliceDkg instances.
func newAliceDkgFromAlice(a *dkg.Alice, version uint) *AliceDkg {
	ad := &AliceDkg{Alice: a}
	ad.steps = []func(*protocol.Message) (*protocol.Message, error){
		// Step 1: receive Bob's seed → commit to Alice's Schnorr proof.
		func(input *protocol.Message) (*protocol.Message, error) {
			bobSeed, err := decodeDkgRound1Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			r2, err := ad.Round2CommitToProof(bobSeed)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound2Output(r2, version)
		},
		// Step 2: receive Bob's Schnorr proof → verify and reveal Alice's proof.
		func(input *protocol.Message) (*protocol.Message, error) {
			proof, err := decodeDkgRound3Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			aliceProof, err := ad.Round4VerifyAndReveal(proof)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound4Output(aliceProof, version)
		},
		// Step 3: receive Bob's OT Round1 → run OT Round2.
		func(input *protocol.Message) (*protocol.Message, error) {
			proof, err := decodeDkgRound5Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			choices, err := ad.Round6OTRound2(proof)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound6Output(choices, version)
		},
		// Step 4: receive OT Round3 challenge → respond.
		func(input *protocol.Message) (*protocol.Message, error) {
			challenge, err := decodeDkgRound7Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			responses, err := ad.Round8OTRound4(challenge)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound8Output(responses, version)
		},
		// Step 5: receive OT Round5 openings → final verification.
		func(input *protocol.Message) (*protocol.Message, error) {
			openings, err := decodeDkgRound9Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if err := ad.Round10OTRound6(openings); err != nil {
				return nil, err
			}
			return nil, nil
		},
	}
	return ad
}

// newBobDkgFromBob is the shared constructor logic for BobDkg instances.
func newBobDkgFromBob(b *dkg.Bob, version uint) *BobDkg {
	bd := &BobDkg{Bob: b}
	bd.steps = []func(*protocol.Message) (*protocol.Message, error){
		// Step 1: no input → generate and send random seed.
		func(*protocol.Message) (*protocol.Message, error) {
			seed, err := bd.Round1GenerateRandomSeed()
			if err != nil {
				return nil, err
			}
			return encodeDkgRound1Output(seed, version)
		},
		// Step 2: receive Alice's commitment → prove Bob's key share.
		func(input *protocol.Message) (*protocol.Message, error) {
			r2, err := decodeDkgRound2Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			bobProof, err := bd.Round3SchnorrProve(r2)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound3Output(bobProof, version)
		},
		// Step 3: receive Alice's revealed proof → verify, decommit, start OT.
		func(input *protocol.Message) (*protocol.Message, error) {
			proof, err := decodeDkgRound4Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			otR1, err := bd.Round5DecommitAndStartOT(proof)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound5Output(otR1, version)
		},
		// Step 4: receive OT Round2 masked choices → send OT challenges.
		func(input *protocol.Message) (*protocol.Message, error) {
			choices, err := decodeDkgRound6Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			challenge, err := bd.Round7OTRound3(choices)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound7Output(challenge, version)
		},
		// Step 5: receive OT responses → verify and send openings.
		func(input *protocol.Message) (*protocol.Message, error) {
			responses, err := decodeDkgRound8Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			openings, err := bd.Round9OTRound5(responses)
			if err != nil {
				return nil, err
			}
			return encodeDkgRound9Output(openings, version)
		},
	}
	return bd
}

// NewAliceDkg creates a DKLS19 DKG iterator for Alice.
// Alice is the responder; she waits for Bob's seed before acting.
func NewAliceDkg(curve *curves.Curve, version uint) *AliceDkg {
	return newAliceDkgFromAlice(dkg.NewAlice(curve), version)
}

// NewAliceDkgWithSecret creates a DKLS19 DKG iterator for Alice using a pre-existing
// secret key share instead of generating a fresh random one.
//
// This is designed for the Shamir+DKLS19 2-of-n hybrid: after a group DKG (e.g. FROST)
// produces Shamir shares, the caller computes the Lagrange-weighted share for this pair
// and passes it here. The DKLS19 DKG then establishes the OT correlations required for
// future signing sessions, while the resulting public key matches the group public key.
//
// secretShare must equal λ_alice · s_alice for the signing pair {alice, bob},
// where λ_alice is Alice's Lagrange coefficient and s_alice is her Shamir share.
func NewAliceDkgWithSecret(curve *curves.Curve, secretShare curves.Scalar, version uint) *AliceDkg {
	return newAliceDkgFromAlice(dkg.NewAliceWithSecret(curve, secretShare), version)
}

// Result encodes Alice's DKG output for use in subsequent signing sessions.
func (a *AliceDkg) Result(version uint) (*protocol.Message, error) {
	if !a.complete() {
		return nil, errors.New("DKLS19: DKG protocol not yet complete")
	}
	if a.Alice == nil {
		return nil, protocol.ErrNotInitialized
	}
	out := a.Output()
	if out == nil {
		return nil, errors.New("DKLS19: DKG Alice output is nil (protocol incomplete)")
	}
	return EncodeAliceDkgOutput(out, version)
}

// NewBobDkg creates a DKLS19 DKG iterator for Bob.
// Bob is the initiator; his first step requires no input.
func NewBobDkg(curve *curves.Curve, version uint) *BobDkg {
	return newBobDkgFromBob(dkg.NewBob(curve), version)
}

// NewBobDkgWithSecret creates a DKLS19 DKG iterator for Bob using a pre-existing
// secret key share instead of generating a fresh random one.
//
// This is the Bob-side counterpart of NewAliceDkgWithSecret; see that function's
// documentation for the intended use case.
//
// secretShare must equal λ_bob · s_bob for the signing pair {alice, bob}.
func NewBobDkgWithSecret(curve *curves.Curve, secretShare curves.Scalar, version uint) *BobDkg {
	return newBobDkgFromBob(dkg.NewBobWithSecret(curve, secretShare), version)
}

// Result encodes Bob's DKG output for use in subsequent signing sessions.
func (b *BobDkg) Result(version uint) (*protocol.Message, error) {
	if !b.complete() {
		return nil, errors.New("DKLS19: DKG protocol not yet complete")
	}
	if b.Bob == nil {
		return nil, protocol.ErrNotInitialized
	}
	out := b.Output()
	if out == nil {
		return nil, errors.New("DKLS19: DKG Bob output is nil (protocol incomplete)")
	}
	return EncodeBobDkgOutput(out, version)
}

// ── Sign constructors ─────────────────────────────────────────────────────────

// NewAliceSign creates a DKLS19 signing iterator for Alice.
func NewAliceSign(curve *curves.Curve, hash hash.Hash, message []byte, dkgResult *protocol.Message, version uint) (*AliceSign, error) {
	aliceOut, err := DecodeAliceDkgResult(dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	a := &AliceSign{Alice: sign.NewAlice(curve, hash, aliceOut)}
	a.steps = []func(*protocol.Message) (*protocol.Message, error){
		// Step 1: no input → generate and send random seed.
		func(*protocol.Message) (*protocol.Message, error) {
			seed, err := a.Round1GenerateRandomSeed()
			if err != nil {
				return nil, err
			}
			return encodeSignRound1Output(seed, version)
		},
		// Step 2: receive Bob's SignRound2Output → produce Alice's sign message.
		func(input *protocol.Message) (*protocol.Message, error) {
			r2, err := decodeSignRound2Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			r3, err := a.Round3Sign(message, r2)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			return encodeSignRound3Output(r3, version)
		},
	}
	return a, nil
}

// NewAliceSignWithTweak creates a DKLS19 signing iterator for Alice with a BIP32 scalar
// tweak applied to her secret key share before signing.
//
// The tweak implements BIP32 child-key derivation at the MPC layer without requiring a
// new DKG session: Alice's effective share becomes sk_A' = sk_A + tweak.  The caller
// must also pass childPublicKey — the BIP32-derived child public key — so that the
// signing protocol's internal ECDSA verification uses the correct public key.
//
// Intended usage:
//
//	tweak, childPubKey, err := bip32.DeriveChildKey(aggregatedPubKey, path)
//	aliceSign, err := NewAliceSignWithTweak(curve, hash, msg, dkgResult, tweak, childPubKey, version)
func NewAliceSignWithTweak(
	curve *curves.Curve,
	hash hash.Hash,
	message []byte,
	dkgResult *protocol.Message,
	tweak curves.Scalar,
	childPublicKey curves.Point,
	version uint,
) (*AliceSign, error) {
	aliceOut, err := DecodeAliceDkgResult(dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	tweakedOut := &dkg.AliceOutput{
		PublicKey:      childPublicKey,
		SecretKeyShare: aliceOut.SecretKeyShare.Add(tweak),
		SeedOtResult:   aliceOut.SeedOtResult,
	}
	a := &AliceSign{Alice: sign.NewAlice(curve, hash, tweakedOut)}
	a.steps = []func(*protocol.Message) (*protocol.Message, error){
		func(*protocol.Message) (*protocol.Message, error) {
			seed, err := a.Round1GenerateRandomSeed()
			if err != nil {
				return nil, err
			}
			return encodeSignRound1Output(seed, version)
		},
		func(input *protocol.Message) (*protocol.Message, error) {
			r2, err := decodeSignRound2Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			r3, err := a.Round3Sign(message, r2)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			return encodeSignRound3Output(r3, version)
		},
	}
	return a, nil
}

// Result always returns an error: Alice does not compute a signature.
func (a *AliceSign) Result(_ uint) (*protocol.Message, error) {
	return nil, errors.New("DKLS19: Alice does not produce a signature")
}

// NewBobSign creates a DKLS19 signing iterator for Bob.
func NewBobSign(curve *curves.Curve, hash hash.Hash, message []byte, dkgResult *protocol.Message, version uint) (*BobSign, error) {
	bobOut, err := DecodeBobDkgResult(dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	b := &BobSign{Bob: sign.NewBob(curve, hash, bobOut)}
	b.steps = []func(*protocol.Message) (*protocol.Message, error){
		// Step 1: receive Alice's seed → initialise Bob's sign state and reply.
		func(input *protocol.Message) (*protocol.Message, error) {
			seed, err := decodeSignRound1Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			r2, err := b.Round2Initialize(seed)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			return encodeSignRound2Output(r2, version)
		},
		// Step 2: receive Alice's sign message → finalise signature.
		func(input *protocol.Message) (*protocol.Message, error) {
			r3, err := decodeSignRound3Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if err = b.Round4Final(message, r3); err != nil {
				return nil, errors.WithStack(err)
			}
			return nil, nil
		},
	}
	return b, nil
}

// NewBobSignWithTweak creates a DKLS19 signing iterator for Bob with a BIP32 child
// public key override.
//
// In the additive secret-sharing scheme (x = sk_A + sk_B), only Alice adds the scalar
// tweak to her share (sk_A' = sk_A + tweak).  Bob's share remains unchanged.  The
// joint child key is then x' = sk_A' + sk_B = x + tweak, as required by BIP32.
//
// The caller must pass the correct childPublicKey (= x'·G) so that Bob's internal
// ECDSA verification uses the derived child key and not the master key.
func NewBobSignWithTweak(
	curve *curves.Curve,
	hash hash.Hash,
	message []byte,
	dkgResult *protocol.Message,
	tweak curves.Scalar,
	childPublicKey curves.Point,
	version uint,
) (*BobSign, error) {
	bobOut, err := DecodeBobDkgResult(dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	// Bob's key share is NOT tweaked; only Alice adds the scalar tweak.
	tweakedOut := &dkg.BobOutput{
		PublicKey:      childPublicKey,
		SecretKeyShare: bobOut.SecretKeyShare,
		SeedOtResult:   bobOut.SeedOtResult,
	}
	b := &BobSign{Bob: sign.NewBob(curve, hash, tweakedOut)}
	b.steps = []func(*protocol.Message) (*protocol.Message, error){
		func(input *protocol.Message) (*protocol.Message, error) {
			seed, err := decodeSignRound1Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			r2, err := b.Round2Initialize(seed)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			return encodeSignRound2Output(r2, version)
		},
		func(input *protocol.Message) (*protocol.Message, error) {
			r3, err := decodeSignRound3Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if err = b.Round4Final(message, r3); err != nil {
				return nil, errors.WithStack(err)
			}
			return nil, nil
		},
	}
	return b, nil
}

// Result returns the completed ECDSA signature produced by Bob.
func (b *BobSign) Result(version uint) (*protocol.Message, error) {
	if !b.complete() {
		return nil, errors.New("DKLS19: signing protocol not yet complete")
	}
	if b.Bob == nil {
		return nil, protocol.ErrNotInitialized
	}
	return encodeSignature(b.Bob.Signature, version)
}

// ── Refresh constructors ──────────────────────────────────────────────────────

// NewAliceRefresh creates a DKLS19 key-refresh iterator for Alice.
func NewAliceRefresh(curve *curves.Curve, dkgResult *protocol.Message, version uint) (*AliceRefresh, error) {
	aliceOut, err := DecodeAliceDkgResult(dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	a := &AliceRefresh{Alice: refresh.NewAlice(curve, aliceOut)}
	a.steps = []func(*protocol.Message) (*protocol.Message, error){
		// Step 1: no input → send Alice's addend k_A.
		func(*protocol.Message) (*protocol.Message, error) {
			kA, err := a.Round1AliceAddend()
			if err != nil {
				return nil, err
			}
			return encodeRefreshRound1Output(kA, version)
		},
		// Step 2: receive Bob's RefreshRound2Output → update share, start OT.
		func(input *protocol.Message) (*protocol.Message, error) {
			r2, err := decodeRefreshRound2Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			choices, err := a.Round3AliceUpdateAndOT(r2)
			if err != nil {
				return nil, err
			}
			return encodeRefreshRound3Output(choices, version)
		},
		// Step 3: OT Round3 challenge → respond.
		func(input *protocol.Message) (*protocol.Message, error) {
			challenges, err := decodeRefreshRound4Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			responses, err := a.Round5OTRound4(challenges)
			if err != nil {
				return nil, err
			}
			return encodeRefreshRound5Output(responses, version)
		},
		// Step 4: OT Round5 openings → final verify.
		func(input *protocol.Message) (*protocol.Message, error) {
			openings, err := decodeRefreshRound6Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			if err := a.Round7OTRound6(openings); err != nil {
				return nil, err
			}
			return nil, nil
		},
	}
	return a, nil
}

// Result encodes Alice's refreshed DKG output.
func (a *AliceRefresh) Result(version uint) (*protocol.Message, error) {
	if !a.complete() {
		return nil, errors.New("DKLS19: refresh protocol not yet complete")
	}
	if a.Alice == nil {
		return nil, protocol.ErrNotInitialized
	}
	out := a.Output()
	if out == nil {
		return nil, errors.New("DKLS19: refresh Alice output is nil (protocol incomplete)")
	}
	return EncodeAliceDkgOutput(out, version)
}

// NewBobRefresh creates a DKLS19 key-refresh iterator for Bob.
func NewBobRefresh(curve *curves.Curve, dkgResult *protocol.Message, version uint) (*BobRefresh, error) {
	bobOut, err := DecodeBobDkgResult(dkgResult)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	b := &BobRefresh{Bob: refresh.NewBob(curve, bobOut)}
	b.steps = []func(*protocol.Message) (*protocol.Message, error){
		// Step 1: receive Alice's addend k_A → update share, start OT, reply.
		func(input *protocol.Message) (*protocol.Message, error) {
			kA, err := decodeRefreshRound1Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			r2, err := b.Round2BobAddendAndOT(kA)
			if err != nil {
				return nil, err
			}
			return encodeRefreshRound2Output(r2, version)
		},
		// Step 2: OT Round2 masked choices → send challenge.
		func(input *protocol.Message) (*protocol.Message, error) {
			choices, err := decodeRefreshRound3Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			challenges, err := b.Round4OTRound3(choices)
			if err != nil {
				return nil, err
			}
			return encodeRefreshRound4Output(challenges, version)
		},
		// Step 3: OT responses → verify and send openings.
		func(input *protocol.Message) (*protocol.Message, error) {
			responses, err := decodeRefreshRound5Output(input)
			if err != nil {
				return nil, errors.WithStack(err)
			}
			openings, err := b.Round6OTRound5(responses)
			if err != nil {
				return nil, err
			}
			return encodeRefreshRound6Output(openings, version)
		},
	}
	return b, nil
}

// Result encodes Bob's refreshed DKG output.
func (b *BobRefresh) Result(version uint) (*protocol.Message, error) {
	if !b.complete() {
		return nil, errors.New("DKLS19: refresh protocol not yet complete")
	}
	if b.Bob == nil {
		return nil, protocol.ErrNotInitialized
	}
	out := b.Output()
	if out == nil {
		return nil, errors.New("DKLS19: refresh Bob output is nil (protocol incomplete)")
	}
	return EncodeBobDkgOutput(out, version)
}
