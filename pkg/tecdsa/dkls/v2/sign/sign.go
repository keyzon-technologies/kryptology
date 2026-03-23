// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package sign implements the 2-of-2 threshold signing protocol of
// [DKLS19](https://eprint.iacr.org/2019/523.pdf), Protocol 3 ("2-Party Signing").
//
// Key differences from DKLs18:
//  1. The joint nonce R is derived with a hash-based binding:
//     R = H(R') · D_B + R'  (where R' = k'_A · D_B), giving a tighter
//     UC proof under the random-oracle model.
//  2. The consistency-check values η_φ and η_sig are computed over updated
//     gamma constructions that match the DKLS19 proof.
//  3. The Merlin transcript domain separator is "DKLS19_Sign_v2" to prevent
//     cross-version replay.
package sign

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"hash"
	"math/big"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/ot/extension/kos"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
)

// multiplicationCount is 3 for the additive secret-sharing variant of DKLS19.
//
// With additive shares (x = sk_A + sk_B, Q = (sk_A+sk_B)·G) two separate OT
// multiplications cover each party's key contribution:
//
//	Multiply 0: (φ + 1/k_A) × (1/k_B)        → nonce inverse 1/k (same as before)
//	Multiply 1: (sk_A/k_A) × (1/k_B)          → Alice's key contribution sk_A/k
//	Multiply 2: (1/k_A)    × (sk_B/k_B)       → Bob's key contribution  sk_B/k
//
// Joint result:
//
//	δ_{s,1}+δ_{r,1}+δ_{s,2}+δ_{r,2} = (sk_A + sk_B)/k = x/k
//
// giving s = H(m)/k + r·x/k = (H(m) + r·x)/k  with Q = x·G. ✓
const multiplicationCount = 3

// Alice holds Alice's state across one signing execution.
// At the end of the joint computation Alice does NOT possess the signature.
type Alice struct {
	hash           hash.Hash
	seedOtResults  *simplest.ReceiverOutput
	secretKeyShare curves.Scalar
	publicKey      curves.Point
	curve          *curves.Curve
	transcript     *merlin.Transcript
}

// Bob holds Bob's state across one signing execution.
// At the end of the joint computation Bob possesses the completed signature.
type Bob struct {
	// Signature is the resulting ECDSA signature — only valid after Round4Final.
	Signature *curves.EcdsaSignature

	hash              hash.Hash
	seedOtResults     *simplest.SenderOutput
	secretKeyShare    curves.Scalar
	publicKey         curves.Point
	transcript        *merlin.Transcript
	multiplyReceivers [multiplicationCount]*MultiplyReceiver
	kB                curves.Scalar
	dB                curves.Point
	curve             *curves.Curve
}

// NewAlice creates an Alice signing instance from the DKG output.
// Returns nil if curve, hash, or dkgOutput is nil.
func NewAlice(curve *curves.Curve, hash hash.Hash, dkgOutput *dkg.AliceOutput) *Alice {
	if curve == nil || hash == nil || dkgOutput == nil {
		return nil
	}
	return &Alice{
		hash:           hash,
		seedOtResults:  dkgOutput.SeedOtResult,
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("DKLS19_Sign_v2"),
	}
}

// NewBob creates a Bob signing instance from the DKG output.
// Returns nil if curve, hash, or dkgOutput is nil.
func NewBob(curve *curves.Curve, hash hash.Hash, dkgOutput *dkg.BobOutput) *Bob {
	if curve == nil || hash == nil || dkgOutput == nil {
		return nil
	}
	return &Bob{
		hash:           hash,
		seedOtResults:  dkgOutput.SeedOtResult,
		curve:          curve,
		secretKeyShare: dkgOutput.SecretKeyShare,
		publicKey:      dkgOutput.PublicKey,
		transcript:     merlin.NewTranscript("DKLS19_Sign_v2"),
	}
}

// SignRound2Output is Bob's initial message to Alice.
type SignRound2Output struct {
	// KosRound1Outputs holds the first cOT round outputs for the two multiplications.
	KosRound1Outputs [multiplicationCount]*kos.Round1Output

	// DB = k_B · G is Bob's nonce contribution.
	DB curves.Point

	// Seed is Bob's random contribution to the session ID.
	Seed [simplest.DigestSize]byte
}

// SignRound3Output is Alice's reply to Bob.
type SignRound3Output struct {
	// MultiplyRound2Outputs holds Alice's cOT replies for both multiplications.
	MultiplyRound2Outputs [multiplicationCount]*MultiplyRound2Output

	// RSchnorrProof is the ZKP for R = k_A · D_B.
	RSchnorrProof *schnorr.Proof

	// RPrime = k'_A · D_B (the blinded nonce before hash-binding).
	RPrime curves.Point

	// EtaPhi and EtaSig are the DKLS19 consistency-check masked values.
	EtaPhi curves.Scalar
	EtaSig curves.Scalar
}

// Round1GenerateRandomSeed is Alice's first move.
// She samples a random 32-byte seed to contribute to the joint session ID.
func (alice *Alice) Round1GenerateRandomSeed() ([simplest.DigestSize]byte, error) {
	seed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(seed[:]); err != nil {
		return seed, errors.Wrap(err, "DKLS19 sign Round1: generating Alice seed")
	}
	alice.transcript.AppendMessage([]byte("dkls19_sign_sid_alice"), seed[:])
	return seed, nil
}

// Round2Initialize is Bob's initial message (Protocol 3, Bob's steps 1–3).
// Bob samples his nonce k_B, computes D_B = k_B · G, prepares the two
// multiplication sub-protocol instances, and returns all data to Alice.
func (bob *Bob) Round2Initialize(aliceSeed [simplest.DigestSize]byte) (*SignRound2Output, error) {
	bobSeed := [simplest.DigestSize]byte{}
	if _, err := rand.Read(bobSeed[:]); err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: generating Bob seed")
	}
	bob.transcript.AppendMessage([]byte("dkls19_sign_sid_alice"), aliceSeed[:])
	bob.transcript.AppendMessage([]byte("dkls19_sign_sid_bob"), bobSeed[:])

	var err error
	sessionID := [simplest.DigestSize]byte{}

	copy(sessionID[:], bob.transcript.ExtractBytes([]byte("dkls19_multiply_recv_0"), simplest.DigestSize))
	bob.multiplyReceivers[0], err = NewMultiplyReceiver(bob.seedOtResults, bob.curve, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: create multiply receiver 0")
	}

	copy(sessionID[:], bob.transcript.ExtractBytes([]byte("dkls19_multiply_recv_1"), simplest.DigestSize))
	bob.multiplyReceivers[1], err = NewMultiplyReceiver(bob.seedOtResults, bob.curve, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: create multiply receiver 1")
	}

	copy(sessionID[:], bob.transcript.ExtractBytes([]byte("dkls19_multiply_recv_2"), simplest.DigestSize))
	bob.multiplyReceivers[2], err = NewMultiplyReceiver(bob.seedOtResults, bob.curve, sessionID)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: create multiply receiver 2")
	}

	out := &SignRound2Output{Seed: bobSeed}
	bob.kB = bob.curve.Scalar.Random(rand.Reader)
	bob.dB = bob.curve.ScalarBaseMult(bob.kB)
	out.DB = bob.dB
	kBInv := bob.curve.Scalar.One().Div(bob.kB)

	// Multiply 0 (nonce): receiver input = 1/k_B
	out.KosRound1Outputs[0], err = bob.multiplyReceivers[0].Round1Initialize(kBInv)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: multiply 0 Round1")
	}
	// Multiply 1 (Alice's key through Bob's nonce): receiver input = 1/k_B.
	// Jointly computes (sk_A/k_A) * (1/k_B) = sk_A/k (Alice's key share of x/k).
	out.KosRound1Outputs[1], err = bob.multiplyReceivers[1].Round1Initialize(kBInv)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: multiply 1 Round1")
	}
	// Multiply 2 (Bob's key contribution): receiver input = sk_B / k_B.
	// Jointly computes (1/k_A) * (sk_B/k_B) = sk_B/k (Bob's key share of x/k).
	out.KosRound1Outputs[2], err = bob.multiplyReceivers[2].Round1Initialize(bob.secretKeyShare.Mul(kBInv))
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round2: multiply 2 Round1")
	}
	return out, nil
}

// Round3Sign is Alice's signing message (Protocol 3, Alice's steps 3–8).
//
// DKLS19 nonce construction (improvement over DKLs18):
//
//	k'_A  ← F_q  (blind nonce)
//	R'    = k'_A · D_B
//	k_A   = H(R') + k'_A      (hash-binding prevents nonce malleability)
//	R     = k_A · D_B         (the true ECDSA nonce point)
//
// Alice feeds (φ+1/k_A), (sk_A/k_A), and (1/k_A) into the three OLE multiplications,
// and computes the masked consistency-check values η_φ and η_sig.
func (alice *Alice) Round3Sign(message []byte, r2 *SignRound2Output) (*SignRound3Output, error) {
	alice.transcript.AppendMessage([]byte("dkls19_sign_sid_bob"), r2.Seed[:])

	multiplySenders := [multiplicationCount]*MultiplySender{}
	var err error
	sessionID := [simplest.DigestSize]byte{}

	copy(sessionID[:], alice.transcript.ExtractBytes([]byte("dkls19_multiply_recv_0"), simplest.DigestSize))
	if multiplySenders[0], err = NewMultiplySender(alice.seedOtResults, alice.curve, sessionID); err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: create multiply sender 0")
	}

	copy(sessionID[:], alice.transcript.ExtractBytes([]byte("dkls19_multiply_recv_1"), simplest.DigestSize))
	if multiplySenders[1], err = NewMultiplySender(alice.seedOtResults, alice.curve, sessionID); err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: create multiply sender 1")
	}

	copy(sessionID[:], alice.transcript.ExtractBytes([]byte("dkls19_multiply_recv_2"), simplest.DigestSize))
	if multiplySenders[2], err = NewMultiplySender(alice.seedOtResults, alice.curve, sessionID); err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: create multiply sender 2")
	}

	out := &SignRound3Output{}

	// --- DKLS19 hash-binding nonce construction ---
	kPrimeA := alice.curve.Scalar.Random(rand.Reader)
	out.RPrime = r2.DB.Mul(kPrimeA) // R' = k'_A · D_B

	rPrimeHashBytes := sha3.Sum256(out.RPrime.ToAffineCompressed())
	rPrimeHash, err := alice.curve.Scalar.SetBytes(rPrimeHashBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: H(R') scalar")
	}
	kA := rPrimeHash.Add(kPrimeA) // k_A = H(R') + k'_A

	// ZKP: prove knowledge of k_A s.t. R = k_A · D_B.
	copy(sessionID[:], alice.transcript.ExtractBytes([]byte("dkls19_schnorr_R"), simplest.DigestSize))
	rProver := schnorr.NewProver(alice.curve, r2.DB, sessionID[:])
	out.RSchnorrProof, err = rProver.Prove(kA)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: Schnorr proof for R")
	}

	// R is the ECDSA nonce point.
	r := out.RSchnorrProof.Statement

	phi := alice.curve.Scalar.Random(rand.Reader)
	kAInv := alice.curve.Scalar.One().Div(kA)

	// Multiply 0 (nonce): sender input = φ + 1/k_A (unchanged from DKLS19 original).
	// Joint result: (φ + 1/k_A)/k_B → θ = 1/(k_A·k_B) after φ cancellation.
	out.MultiplyRound2Outputs[0], err = multiplySenders[0].Round2Multiply(
		phi.Add(kAInv), r2.KosRound1Outputs[0])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: multiply 0 Round2")
	}

	// Multiply 1 (Alice's key contribution): sender input = sk_A / k_A.
	// Bob's receiver has 1/k_B → joint result: sk_A/(k_A·k_B) = sk_A/k.
	out.MultiplyRound2Outputs[1], err = multiplySenders[1].Round2Multiply(
		alice.secretKeyShare.Mul(kAInv), r2.KosRound1Outputs[1])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: multiply 1 Round2")
	}

	// Multiply 2 (Bob's key contribution): sender input = 1/k_A.
	// Bob's receiver has sk_B/k_B → joint result: sk_B/(k_A·k_B) = sk_B/k.
	out.MultiplyRound2Outputs[2], err = multiplySenders[2].Round2Multiply(
		kAInv, r2.KosRound1Outputs[2])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: multiply 2 Round2")
	}

	// --- Compute η_φ (nonce consistency check) ---
	// γ_1 = k_A·φ·G + G − r·δ_{s,0}
	one := alice.curve.Scalar.One()
	gamma1 := alice.curve.ScalarBaseMult(kA.Mul(phi).Add(one))
	gamma1 = gamma1.Add(r.Mul(multiplySenders[0].outputAdditiveShare.Neg()))

	gamma1HashBytes := sha3.Sum256(gamma1.ToAffineCompressed())
	gamma1Hash, err := alice.curve.Scalar.SetBytes(gamma1HashBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: H(γ_1) scalar")
	}
	out.EtaPhi = gamma1Hash.Add(phi)

	// --- Compute η_sig (signature share consistency check) ---
	if _, err = alice.hash.Write(message); err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: hashing message")
	}
	digest := alice.hash.Sum(nil)
	hm, err := alice.curve.Scalar.SetBytes(digest)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: H(m) scalar")
	}

	compressed := r.ToAffineCompressed()
	if len(compressed) != 33 {
		return nil, errors.New("DKLS19 sign Round3: compressed point must be 33 bytes")
	}
	rX, err := alice.curve.Scalar.SetBytes(compressed[1:])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: R_x scalar")
	}

	// Additive key contributions: δ_{s,1} + δ_{s,2} = sk_A/k + sk_B/k (Alice's sender shares).
	keyShareSenderSum := multiplySenders[1].outputAdditiveShare.Add(multiplySenders[2].outputAdditiveShare)

	// sig_A = H(m) · δ_{s,0} + R_x · (δ_{s,1} + δ_{s,2})
	sigA := hm.Mul(multiplySenders[0].outputAdditiveShare).Add(rX.Mul(keyShareSenderSum))

	// γ_2 = Q · δ_{s,0} − (δ_{s,1} + δ_{s,2}) · G
	// Bob will compute (δ_{r,1}+δ_{r,2})·G − θ·Q, and both should give the same point.
	gamma2 := alice.publicKey.Mul(multiplySenders[0].outputAdditiveShare)
	gamma2 = gamma2.Add(alice.curve.ScalarBaseMult(keyShareSenderSum.Neg()))

	gamma2HashBytes := sha3.Sum256(gamma2.ToAffineCompressed())
	gamma2Hash, err := alice.curve.Scalar.SetBytes(gamma2HashBytes[:])
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 sign Round3: H(γ_2) scalar")
	}
	out.EtaSig = gamma2Hash.Add(sigA)
	return out, nil
}

// Round4Final is Bob's last step (Protocol 3, Bob's steps 3–10).
// Bob finalises both OLE multiplications, reconstructs R from R' using
// the same hash-binding as Alice, verifies Alice's Schnorr proof, recovers
// φ and θ from the consistency-check values, assembles s = sig_A + sig_B, and
// verifies the completed ECDSA signature.
func (bob *Bob) Round4Final(message []byte, r3 *SignRound3Output) error {
	if err := bob.multiplyReceivers[0].Round3Multiply(r3.MultiplyRound2Outputs[0]); err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: multiply 0 Round3")
	}
	if err := bob.multiplyReceivers[1].Round3Multiply(r3.MultiplyRound2Outputs[1]); err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: multiply 1 Round3")
	}
	if err := bob.multiplyReceivers[2].Round3Multiply(r3.MultiplyRound2Outputs[2]); err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: multiply 2 Round3")
	}

	// Reconstruct R = H(R') · D_B + R'  (Bob mirrors Alice's hash-binding).
	rPrimeHashBytes := sha3.Sum256(r3.RPrime.ToAffineCompressed())
	rPrimeHash, err := bob.curve.Scalar.SetBytes(rPrimeHashBytes[:])
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: H(R') scalar")
	}
	r := bob.dB.Mul(rPrimeHash).Add(r3.RPrime)

	// Override Alice's statement with Bob's independently computed R.
	r3.RSchnorrProof.Statement = r
	sessionID := [simplest.DigestSize]byte{}
	copy(sessionID[:], bob.transcript.ExtractBytes([]byte("dkls19_schnorr_R"), simplest.DigestSize))
	if err = schnorr.Verify(r3.RSchnorrProof, bob.curve, bob.dB, sessionID[:]); err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: verify Alice's Schnorr proof for R")
	}

	// Extract R_x and record V (recovery bit).
	compressed := r.ToAffineCompressed()
	if len(compressed) != 33 {
		return errors.New("DKLS19 sign Round4: compressed R must be 33 bytes")
	}
	rY := compressed[0] & 0x1
	rX, err := bob.curve.Scalar.SetBytes(compressed[1:])
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: R_x scalar")
	}
	bob.Signature = &curves.EcdsaSignature{
		R: rX.Add(bob.curve.Scalar.Zero()).BigInt(),
		V: int(rY),
	}

	// Recover φ from η_φ.
	gamma1 := r.Mul(bob.multiplyReceivers[0].outputAdditiveShare)
	gamma1HashBytes := sha3.Sum256(gamma1.ToAffineCompressed())
	gamma1Hash, err := bob.curve.Scalar.SetBytes(gamma1HashBytes[:])
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: H(γ_1) scalar")
	}
	phi := r3.EtaPhi.Sub(gamma1Hash)

	// θ = δ_{r,0} − φ / k_B
	theta := bob.multiplyReceivers[0].outputAdditiveShare.Sub(phi.Div(bob.kB))

	// Hash the message.
	if _, err = bob.hash.Write(message); err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: hashing message")
	}
	digestBytes := bob.hash.Sum(nil)
	hm, err := bob.curve.Scalar.SetBytes(digestBytes)
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: H(m) scalar")
	}

	capitalR, err := bob.curve.Scalar.SetBigInt(bob.Signature.R)
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: R as scalar")
	}

	// Additive key contributions: δ_{r,1} + δ_{r,2} = sk_A/k + sk_B/k (Bob's receiver shares).
	keyShareReceiverSum := bob.multiplyReceivers[1].outputAdditiveShare.Add(bob.multiplyReceivers[2].outputAdditiveShare)

	// sig_B = H(m) · θ + R_x · (δ_{r,1} + δ_{r,2})
	sigB := hm.Mul(theta).Add(capitalR.Mul(keyShareReceiverSum))

	// Recover sig_A from η_sig.
	// γ_2 = (δ_{r,1} + δ_{r,2}) · G − θ · Q
	// Alice computed: Q · δ_{s,0} − (δ_{s,1}+δ_{s,2}) · G; by the OLE guarantee these are equal.
	gamma2 := bob.curve.ScalarBaseMult(keyShareReceiverSum)
	gamma2 = gamma2.Add(bob.publicKey.Mul(theta.Neg()))
	gamma2HashBytes := sha3.Sum256(gamma2.ToAffineCompressed())
	gamma2Hash, err := bob.curve.Scalar.SetBytes(gamma2HashBytes[:])
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: H(γ_2) scalar")
	}

	// s = sig_B + (η_sig − H(γ_2))
	scalarS := sigB.Add(r3.EtaSig.Sub(gamma2Hash))
	bob.Signature.S = scalarS.BigInt()

	// Normalise s to the lower half of the group order (low-s form).
	if bob.Signature.S.Bit(255) == 1 {
		bob.Signature.S = scalarS.Neg().BigInt()
		bob.Signature.V ^= 1
	}

	// Final ECDSA verification.
	uncompressed := bob.publicKey.ToAffineUncompressed()
	if len(uncompressed) != 65 {
		return errors.New("DKLS19 sign Round4: uncompressed public key must be 65 bytes")
	}
	x := new(big.Int).SetBytes(uncompressed[1:33])
	y := new(big.Int).SetBytes(uncompressed[33:])
	ellipticCurve, err := bob.curve.ToEllipticCurve()
	if err != nil {
		return errors.Wrap(err, "DKLS19 sign Round4: curve conversion")
	}
	if !ecdsa.Verify(&ecdsa.PublicKey{Curve: ellipticCurve, X: x, Y: y},
		digestBytes, bob.Signature.R, bob.Signature.S) {
		return fmt.Errorf("DKLS19 sign Round4: final ECDSA signature failed to verify")
	}
	return nil
}
