// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0

// Package silent implements a compact "lazy" seed-OT whose stored state is ~129 bytes
// per pair versus ~24 KB for the Simplest OT it replaces.
//
// # Trade-off
//
// Storage is reduced at the cost of one extra signing round (Alice sends 8 KB of
// ephemeral EC points to Bob). The overall signing round count stays the same because
// Alice's ephemeral points are bundled with her existing Round-1 seed message.
//
// # Protocol summary
//
// DKG setup (replaces 7-round Simplest OT, runs once per wallet pair):
//
//	NewSender  → Bob   generates b, B = b·G, Schnorr proof of b
//	NewReceiver← Alice verifies proof, generates (a_master, choice_bits), stores B
//
// Storage per pair:
//
//	Alice : MasterScalar (32 B) + PackedChoiceBits (32 B) + SenderPublicKey (33 B) = 97 B
//	Bob   : SecretKey (32 B) + PublicKey (33 B)                                    = 65 B
//	Total : 162 B  vs ~24 576 B for Simplest OT  (≈ 150× reduction)
//
// Signing (called once per session):
//
//	Alice.EphemeralPoints  → {A_i = a_i·G + w_i·B}  i=0…255   (8 448 B, sent to Bob)
//	Alice.ExpandReceiver   → *simplest.ReceiverOutput  (computed locally)
//	Bob.ExpandSender(A_i)  → *simplest.SenderOutput   (computed from Alice's points)
//
// Both expanded outputs are passed directly to the KOS OT-extension layer (unchanged).
package silent

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"fmt"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
	"golang.org/x/crypto/sha3"
)

const (
	// BatchSize is the number of base OTs produced. Must equal kos.Kappa (256).
	BatchSize = 256

	digestSize = 32
)

// SenderOutput is Bob's compact silent-OT state (replaces simplest.SenderOutput).
// Bob retains his DH scalar so he can regenerate the OT encryption keys at signing
// time once Alice sends her ephemeral points {A_i}.
type SenderOutput struct {
	// SecretKey is the 32-byte scalar b (Bob's DH secret).
	SecretKey []byte
	// PublicKey is the 33-byte compressed point B = b·G.
	PublicKey []byte
}

// ReceiverOutput is Alice's compact silent-OT state (replaces simplest.ReceiverOutput).
type ReceiverOutput struct {
	// MasterScalar is a 32-byte seed; a_i = PRF(MasterScalar, i).
	MasterScalar []byte
	// PackedChoiceBits holds one choice bit per OT (256 bits = 32 bytes).
	PackedChoiceBits []byte
	// SenderPublicKey is the 33-byte compressed point B = b·G (Bob's DH public key).
	SenderPublicKey []byte
	// RandomChoiceBits is the unpacked choice vector — derived from PackedChoiceBits,
	// never persisted.
	RandomChoiceBits []int
}

// receiverOutputWire is the serialised form of ReceiverOutput.
// RandomChoiceBits is omitted because it is fully derivable from PackedChoiceBits.
type receiverOutputWire struct {
	MasterScalar     []byte
	PackedChoiceBits []byte
	SenderPublicKey  []byte
}

// GobEncode omits RandomChoiceBits (derived field) to keep the stored size minimal.
func (r ReceiverOutput) GobEncode() ([]byte, error) {
	buf := new(bytes.Buffer)
	if err := gob.NewEncoder(buf).Encode(receiverOutputWire{
		MasterScalar:     r.MasterScalar,
		PackedChoiceBits: r.PackedChoiceBits,
		SenderPublicKey:  r.SenderPublicKey,
	}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// GobDecode reconstructs RandomChoiceBits from PackedChoiceBits after decoding.
func (r *ReceiverOutput) GobDecode(data []byte) error {
	var w receiverOutputWire
	if err := gob.NewDecoder(bytes.NewReader(data)).Decode(&w); err != nil {
		return err
	}
	r.MasterScalar = w.MasterScalar
	r.PackedChoiceBits = w.PackedChoiceBits
	r.SenderPublicKey = w.SenderPublicKey
	r.RandomChoiceBits = unpackChoiceBits(w.PackedChoiceBits, BatchSize)
	return nil
}

// NewSender generates Bob's silent-OT DKG state and a Schnorr proof of the DH secret.
// Alice must verify this proof before trusting SenderOutput.PublicKey.
func NewSender(curve *curves.Curve, sessionID []byte) (*SenderOutput, *schnorr.Proof, error) {
	b := curve.Scalar.Random(rand.Reader)
	B := curve.ScalarBaseMult(b)
	prover := schnorr.NewProver(curve, nil, sessionID)
	proof, err := prover.Prove(b)
	if err != nil {
		return nil, nil, fmt.Errorf("silent OT NewSender: Schnorr proof: %w", err)
	}
	return &SenderOutput{
		SecretKey: b.Bytes(),
		PublicKey: B.ToAffineCompressed(),
	}, proof, nil
}

// NewReceiver generates Alice's silent-OT DKG state.
// senderProof is Bob's Schnorr proof; senderProofSessionID is the agreed session ID.
// Returns an error if the proof fails to verify.
func NewReceiver(curve *curves.Curve, senderProof *schnorr.Proof, senderProofSessionID []byte) (*ReceiverOutput, error) {
	if err := schnorr.Verify(senderProof, curve, nil, senderProofSessionID); err != nil {
		return nil, fmt.Errorf("silent OT NewReceiver: verify sender proof: %w", err)
	}
	master := make([]byte, digestSize)
	if _, err := rand.Read(master); err != nil {
		return nil, fmt.Errorf("silent OT NewReceiver: generate master scalar: %w", err)
	}
	packed := make([]byte, BatchSize/8)
	if _, err := rand.Read(packed); err != nil {
		return nil, fmt.Errorf("silent OT NewReceiver: generate choice bits: %w", err)
	}
	return &ReceiverOutput{
		MasterScalar:     master,
		PackedChoiceBits: packed,
		SenderPublicKey:  senderProof.Statement.ToAffineCompressed(),
		RandomChoiceBits: unpackChoiceBits(packed, BatchSize),
	}, nil
}

// EphemeralPoints computes {A_i = a_i·G + w_i·B} from Alice's stored state.
// Alice sends these BatchSize EC points to Bob at the beginning of each signing session.
func (r *ReceiverOutput) EphemeralPoints(curve *curves.Curve) ([]curves.Point, error) {
	B, err := curve.Point.FromAffineCompressed(r.SenderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("silent OT EphemeralPoints: decode sender public key: %w", err)
	}
	pts := make([]curves.Point, BatchSize)
	for i := 0; i < BatchSize; i++ {
		ai, err := deriveScalar(curve, r.MasterScalar, i)
		if err != nil {
			return nil, fmt.Errorf("silent OT EphemeralPoints[%d]: %w", i, err)
		}
		// A_i = a_i·G
		pt := curve.ScalarBaseMult(ai)
		// A_i += w_i·B (add B if choice bit is 1)
		if r.RandomChoiceBits[i] == 1 {
			pt = pt.Add(B)
		}
		pts[i] = pt
	}
	return pts, nil
}

// ExpandReceiver regenerates Alice's simplest-compatible OT decryption keys from
// her stored master scalar. Call this at signing time before the KOS extension.
//
// sessionID should be a fresh per-signing session identifier (e.g., derived from
// the Merlin transcript) so that keys are fresh for every signing session.
func (r *ReceiverOutput) ExpandReceiver(curve *curves.Curve, sessionID [digestSize]byte) (*simplest.ReceiverOutput, error) {
	B, err := curve.Point.FromAffineCompressed(r.SenderPublicKey)
	if err != nil {
		return nil, fmt.Errorf("silent OT ExpandReceiver: decode sender public key: %w", err)
	}
	out := &simplest.ReceiverOutput{
		PackedRandomChoiceBits:  r.PackedChoiceBits,
		RandomChoiceBits:        r.RandomChoiceBits,
		OneTimePadDecryptionKey: make([]simplest.OneTimePadDecryptionKey, BatchSize),
	}
	for i := 0; i < BatchSize; i++ {
		ai, err := deriveScalar(curve, r.MasterScalar, i)
		if err != nil {
			return nil, fmt.Errorf("silent OT ExpandReceiver[%d]: %w", i, err)
		}
		// rho = B^{a_i} = (b·G)^{a_i} — ECDH shared secret with Bob's key
		rho := B.Mul(ai)
		h := sha3.New256()
		h.Write(sessionID[:])
		h.Write([]byte{byte(i)})
		h.Write(rho.ToAffineCompressed())
		copy(out.OneTimePadDecryptionKey[i][:], h.Sum(nil))
	}
	return out, nil
}

// ExpandSender regenerates Bob's simplest-compatible OT encryption keys.
// pts must be the BatchSize ephemeral points {A_i} received from Alice at signing time.
//
// sessionID must match the value passed to Alice's ExpandReceiver call for the
// same signing session.
func (s *SenderOutput) ExpandSender(curve *curves.Curve, pts []curves.Point, sessionID [digestSize]byte) (*simplest.SenderOutput, error) {
	if len(pts) != BatchSize {
		return nil, fmt.Errorf("silent OT ExpandSender: expected %d points, got %d", BatchSize, len(pts))
	}
	b, err := curve.Scalar.SetBytes(s.SecretKey)
	if err != nil {
		return nil, fmt.Errorf("silent OT ExpandSender: decode secret key: %w", err)
	}
	B, err := curve.Point.FromAffineCompressed(s.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("silent OT ExpandSender: decode public key: %w", err)
	}
	negB := B.Neg()
	out := &simplest.SenderOutput{
		OneTimePadEncryptionKeys: make([]simplest.OneTimePadEncryptionKeys, BatchSize),
	}
	for i := 0; i < BatchSize; i++ {
		Ai := pts[i]
		// rho_0 = A_i^b  (ECDH for option 0)
		rho0 := Ai.Mul(b)
		// rho_1 = (A_i − B)^b  (ECDH for option 1)
		rho1 := Ai.Add(negB).Mul(b)
		for j, rho := range []curves.Point{rho0, rho1} {
			h := sha3.New256()
			h.Write(sessionID[:])
			h.Write([]byte{byte(i)})
			h.Write(rho.ToAffineCompressed())
			copy(out.OneTimePadEncryptionKeys[i][j][:], h.Sum(nil))
		}
	}
	return out, nil
}

// EncodeEphemeralPoints serialises the BatchSize EC points for transmission.
func EncodeEphemeralPoints(pts []curves.Point) ([][]byte, error) {
	if len(pts) != BatchSize {
		return nil, fmt.Errorf("silent OT EncodeEphemeralPoints: expected %d points, got %d", BatchSize, len(pts))
	}
	out := make([][]byte, BatchSize)
	for i, p := range pts {
		out[i] = p.ToAffineCompressed()
	}
	return out, nil
}

// DecodeEphemeralPoints deserialises the BatchSize compressed EC points.
func DecodeEphemeralPoints(curve *curves.Curve, encoded [][]byte) ([]curves.Point, error) {
	if len(encoded) != BatchSize {
		return nil, fmt.Errorf("silent OT DecodeEphemeralPoints: expected %d points, got %d", BatchSize, len(encoded))
	}
	pts := make([]curves.Point, BatchSize)
	var err error
	for i, b := range encoded {
		if pts[i], err = curve.Point.FromAffineCompressed(b); err != nil {
			return nil, fmt.Errorf("silent OT DecodeEphemeralPoints[%d]: %w", i, err)
		}
	}
	return pts, nil
}

// deriveScalar derives a deterministic per-OT scalar a_i from the master scalar seed.
// Uses SHAKE-256 with a domain separator for domain separation.
func deriveScalar(curve *curves.Curve, master []byte, i int) (curves.Scalar, error) {
	h := sha3.NewShake256()
	_, _ = h.Write([]byte("silent_ot_scalar_v1"))
	_, _ = h.Write(master)
	_, _ = h.Write([]byte{byte(i >> 8), byte(i)})
	wide := make([]byte, 64)
	_, _ = h.Read(wide)
	return curve.Scalar.SetBytesWide(wide)
}

// unpackChoiceBits unpacks n bits from a packed byte slice into a []int slice.
func unpackChoiceBits(packed []byte, n int) []int {
	bits := make([]int, n)
	for i := 0; i < n; i++ {
		bits[i] = int((packed[i>>3] >> (i & 7)) & 1)
	}
	return bits
}
