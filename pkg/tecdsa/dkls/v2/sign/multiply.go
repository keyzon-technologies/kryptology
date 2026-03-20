// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// This file implements the Oblivious Linear Evaluation (OLE / Multiplication)
// sub-protocol from DKLS19, Protocol 4.
//
// Reference: https://eprint.iacr.org/2019/523.pdf – Section 3.2 (Protocol 4)
//
// Compared with the DKLs18 version (Protocol 5):
//   - The Fiat–Shamir transcript uses the domain separator "DKLS19_Multiply_v2"
//     (ensuring cryptographic separation from any v1 session).
//   - The gadget-vector derivation uses an updated cSHAKE256 domain string so
//     that the public random vectors for v1 and v2 are independent.
//   - The challenge-response check (Bob's step 6) follows the same algebraic
//     structure as DKLs18 but is documented per DKLS19.
package sign

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"math/big"

	"github.com/gtank/merlin"
	"github.com/pkg/errors"
	"golang.org/x/crypto/sha3"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/ot/extension/kos"
)

// MultiplySender holds Alice's state for one execution of the multiply sub-protocol.
// Alice plays the "sender" role: she holds input α ∈ F_q and learns additive share δ_s.
type MultiplySender struct {
	cOtSender           *kos.Sender
	outputAdditiveShare curves.Scalar // δ_s such that δ_s + δ_r = α · β  (mod q)
	gadget              [kos.L]curves.Scalar
	curve               *curves.Curve
	transcript          *merlin.Transcript
	uniqueSessionId     [simplest.DigestSize]byte
}

// MultiplyReceiver holds Bob's state for one execution of the multiply sub-protocol.
// Bob plays the "receiver" role: he holds input β ∈ F_q and learns additive share δ_r.
type MultiplyReceiver struct {
	cOtReceiver         *kos.Receiver
	outputAdditiveShare curves.Scalar // δ_r such that δ_s + δ_r = α · β  (mod q)
	omega               [kos.COtBlockSizeBytes]byte
	gadget              [kos.L]curves.Scalar
	curve               *curves.Curve
	transcript          *merlin.Transcript
	uniqueSessionId     [simplest.DigestSize]byte
}

// MultiplyRound2Output is Alice's message to Bob in round 2 of the multiply sub-protocol.
type MultiplyRound2Output struct {
	// COTRound2Output is the cOT extension payload.
	COTRound2Output *kos.Round2Output

	// R[j] = Σ_k χ_k · tA_{j,k} — Alice's per-row consistency-check values.
	R [kos.L]curves.Scalar

	// U = χ_0 · α + χ_1 · α̂ — the masked-input value used in Bob's check.
	U curves.Scalar
}

// dkls19GadgetVector builds the structured gadget vector g ∈ F_q^L.
//
// The first κ entries are canonical powers of two: g_i = 2^i.
// The remaining L−κ entries are pseudorandom scalars from cSHAKE256 with the
// DKLS19-specific domain separator, keeping v1 and v2 instances independent.
func dkls19GadgetVector(curve *curves.Curve) ([kos.L]curves.Scalar, error) {
	var err error
	gadget := [kos.L]curves.Scalar{}
	for i := 0; i < kos.Kappa; i++ {
		gadget[i], err = curve.Scalar.SetBigInt(new(big.Int).Lsh(big.NewInt(1), uint(i)))
		if err != nil {
			return gadget, errors.Wrap(err, "DKLS19 gadget: power-of-2 entry")
		}
	}
	// Updated domain separator distinguishes the v2 gadget from v1.
	shake := sha3.NewCShake256(nil, []byte("DKLS19 gadget vector v2"))
	for i := kos.Kappa; i < kos.L; i++ {
		buf := [simplest.DigestSize]byte{}
		if _, err = shake.Read(buf[:]); err != nil {
			return gadget, errors.Wrap(err, "DKLS19 gadget: cSHAKE read")
		}
		gadget[i], err = curve.Scalar.SetBytes(buf[:])
		if err != nil {
			return gadget, errors.Wrap(err, "DKLS19 gadget: random entry")
		}
	}
	return gadget, nil
}

// NewMultiplySender creates an Alice-side multiply instance.
// seedOtResults must be the ReceiverOutput from the DKG seed OT.
func NewMultiplySender(
	seedOtResults *simplest.ReceiverOutput,
	curve *curves.Curve,
	uniqueSessionId [simplest.DigestSize]byte,
) (*MultiplySender, error) {
	gadget, err := dkls19GadgetVector(curve)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 NewMultiplySender")
	}
	transcript := merlin.NewTranscript("DKLS19_Multiply_v2")
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	return &MultiplySender{
		cOtSender:       kos.NewCOtSender(seedOtResults, curve),
		gadget:          gadget,
		curve:           curve,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
	}, nil
}

// NewMultiplyReceiver creates a Bob-side multiply instance.
// seedOtResults must be the SenderOutput from the DKG seed OT.
func NewMultiplyReceiver(
	seedOtResults *simplest.SenderOutput,
	curve *curves.Curve,
	uniqueSessionId [simplest.DigestSize]byte,
) (*MultiplyReceiver, error) {
	gadget, err := dkls19GadgetVector(curve)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 NewMultiplyReceiver")
	}
	transcript := merlin.NewTranscript("DKLS19_Multiply_v2")
	transcript.AppendMessage([]byte("session_id"), uniqueSessionId[:])
	return &MultiplyReceiver{
		cOtReceiver:     kos.NewCOtReceiver(seedOtResults, curve),
		gadget:          gadget,
		curve:           curve,
		transcript:      transcript,
		uniqueSessionId: uniqueSessionId,
	}, nil
}

// encode converts Bob's scalar β into the packed OT choice vector ω ∈ {0,1}^L.
//
// DKLS19 Protocol 4, step 3 (identical in structure to DKLs18 Algorithm 5):
// To prevent selective-failure attacks, Bob subtracts a random linear combination
// of the public random gadget entries from β before packing into the choice bits.
func (receiver *MultiplyReceiver) encode(beta curves.Scalar) ([kos.COtBlockSizeBytes]byte, error) {
	encoding := [kos.COtBlockSizeBytes]byte{}
	betaMinusDot := beta.Bytes()

	// γ ∈ {0,1}^{L−κ} — the high portion of the choice vector, sampled uniformly.
	if _, err := rand.Read(encoding[kos.KappaBytes:]); err != nil {
		return encoding, errors.Wrap(err, "DKLS19 encode: sample γ")
	}

	for j := kos.Kappa; j < kos.L; j++ {
		jthBitOfGamma := simplest.ExtractBitFromByteVector(encoding[:], j)
		opt0, err := receiver.curve.Scalar.SetBytes(betaMinusDot)
		if err != nil {
			return encoding, errors.Wrap(err, "DKLS19 encode: opt0 SetBytes")
		}
		opt0Bytes := opt0.Bytes()
		opt1Bytes := opt0.Sub(receiver.gadget[j]).Bytes()
		betaMinusDot = opt0Bytes
		subtle.ConstantTimeCopy(int(jthBitOfGamma), betaMinusDot, opt1Bytes)
	}
	// The low κ bytes store β − ⟨g_R, γ⟩ in the reversed (little-endian) layout.
	copy(encoding[0:kos.KappaBytes], reverseScalarBytes(betaMinusDot))
	return encoding, nil
}

// reverseScalarBytes returns a copy of b with its bytes in reverse order.
// The kos package expects the scalar in little-endian layout in the choice vector.
func reverseScalarBytes(b []byte) []byte {
	out := make([]byte, len(b))
	for i, v := range b {
		out[len(b)-1-i] = v
	}
	return out
}

// Round1Initialize is Bob's opening message (Protocol 4, receiver steps 1–3).
func (receiver *MultiplyReceiver) Round1Initialize(beta curves.Scalar) (*kos.Round1Output, error) {
	var err error
	if receiver.omega, err = receiver.encode(beta); err != nil {
		return nil, errors.Wrap(err, "DKLS19 multiply Round1: encode β")
	}
	round1Output, err := receiver.cOtReceiver.Round1Initialize(receiver.uniqueSessionId, receiver.omega)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 multiply Round1: cOT initialize")
	}
	for i := 0; i < kos.Kappa; i++ {
		receiver.transcript.AppendMessage(
			[]byte(fmt.Sprintf("row %d of U", i)), round1Output.U[i][:])
	}
	receiver.transcript.AppendMessage([]byte("wPrime"), round1Output.WPrime[:])
	receiver.transcript.AppendMessage([]byte("vPrime"), round1Output.VPrime[:])
	return round1Output, nil
}

// Round2Multiply is Alice's reply (Protocol 4, sender steps 3–7).
func (sender *MultiplySender) Round2Multiply(alpha curves.Scalar, round1Output *kos.Round1Output) (*MultiplyRound2Output, error) {
	alphaHat := sender.curve.Scalar.Random(rand.Reader)

	var input [kos.L][kos.OtWidth]curves.Scalar
	for j := 0; j < kos.L; j++ {
		input[j][0] = alpha
		input[j][1] = alphaHat
	}

	round2Output := &MultiplyRound2Output{}
	var err error
	round2Output.COTRound2Output, err = sender.cOtSender.Round2Transfer(
		sender.uniqueSessionId, input, round1Output)
	if err != nil {
		return nil, errors.Wrap(err, "DKLS19 multiply Round2: cOT transfer")
	}

	// Sync transcript with the receiver's Round1 entries.
	for i := 0; i < kos.Kappa; i++ {
		sender.transcript.AppendMessage(
			[]byte(fmt.Sprintf("row %d of U", i)), round1Output.U[i][:])
	}
	sender.transcript.AppendMessage([]byte("wPrime"), round1Output.WPrime[:])
	sender.transcript.AppendMessage([]byte("vPrime"), round1Output.VPrime[:])

	// Append Alice's cOT Tau rows.
	const chiWidth = 2
	for i := 0; i < kos.Kappa; i++ {
		for k := 0; k < chiWidth; k++ {
			sender.transcript.AppendMessage(
				[]byte(fmt.Sprintf("row %d of Tau", i)),
				round2Output.COTRound2Output.Tau[i][k].Bytes())
		}
	}

	// Draw χ ∈ F_q^2 from the Fiat–Shamir transcript.
	chi := make([]curves.Scalar, chiWidth)
	for k := 0; k < chiWidth; k++ {
		b := sender.transcript.ExtractBytes(
			[]byte(fmt.Sprintf("draw challenge chi %d", k)), kos.KappaBytes)
		chi[k], err = sender.curve.Scalar.SetBytes(b)
		if err != nil {
			return nil, errors.Wrap(err, "DKLS19 multiply Round2: derive χ")
		}
	}

	// Compute δ_s = Σ_j g_j · tA_{j,0}  and  R[j] = Σ_k χ_k · tA_{j,k}.
	sender.outputAdditiveShare = sender.curve.Scalar.Zero()
	for j := 0; j < kos.L; j++ {
		round2Output.R[j] = sender.curve.Scalar.Zero()
		for k := 0; k < chiWidth; k++ {
			round2Output.R[j] = round2Output.R[j].Add(
				chi[k].Mul(sender.cOtSender.OutputAdditiveShares[j][k]))
		}
		sender.outputAdditiveShare = sender.outputAdditiveShare.Add(
			sender.gadget[j].Mul(sender.cOtSender.OutputAdditiveShares[j][0]))
	}

	// U = χ_0 · α + χ_1 · α̂.
	round2Output.U = chi[0].Mul(alpha).Add(chi[1].Mul(alphaHat))
	return round2Output, nil
}

// Round3Multiply is Bob's final step (Protocol 4, receiver steps 3 and 6).
func (receiver *MultiplyReceiver) Round3Multiply(round2Output *MultiplyRound2Output) error {
	const chiWidth = 2

	// Append Alice's Tau rows before drawing the same χ.
	for i := 0; i < kos.Kappa; i++ {
		for k := 0; k < chiWidth; k++ {
			receiver.transcript.AppendMessage(
				[]byte(fmt.Sprintf("row %d of Tau", i)),
				round2Output.COTRound2Output.Tau[i][k].Bytes())
		}
	}

	if err := receiver.cOtReceiver.Round3Transfer(round2Output.COTRound2Output); err != nil {
		return errors.Wrap(err, "DKLS19 multiply Round3: cOT transfer")
	}

	chi := make([]curves.Scalar, chiWidth)
	var err error
	for k := 0; k < chiWidth; k++ {
		b := receiver.transcript.ExtractBytes(
			[]byte(fmt.Sprintf("draw challenge chi %d", k)), kos.KappaBytes)
		chi[k], err = receiver.curve.Scalar.SetBytes(b)
		if err != nil {
			return errors.Wrap(err, "DKLS19 multiply Round3: derive χ")
		}
	}

	receiver.outputAdditiveShare = receiver.curve.Scalar.Zero()
	for j := 0; j < kos.L; j++ {
		// LHS = R[j] + Σ_k χ_k · tB_{j,k}.
		lhs := round2Output.R[j]
		for k := 0; k < chiWidth; k++ {
			lhs = lhs.Add(chi[k].Mul(receiver.cOtReceiver.OutputAdditiveShares[j][k]))
		}

		// RHS = ω_j · U  (constant-time selection to avoid leaking ω_j).
		rhs := [simplest.DigestSize]byte{}
		jthBit := simplest.ExtractBitFromByteVector(receiver.omega[:], j)
		subtle.ConstantTimeCopy(int(jthBit), rhs[:], round2Output.U.Bytes())

		if subtle.ConstantTimeCompare(rhs[:], lhs.Bytes()) != 1 {
			return errors.New("DKLS19 multiply Round3: consistency check failed")
		}

		receiver.outputAdditiveShare = receiver.outputAdditiveShare.Add(
			receiver.gadget[j].Mul(receiver.cOtReceiver.OutputAdditiveShares[j][0]))
	}
	return nil
}
