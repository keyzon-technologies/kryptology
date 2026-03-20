// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v2

import (
	"bytes"
	"encoding/gob"
	"sync"

	"github.com/pkg/errors"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
	"github.com/keyzon-technologies/kryptology/pkg/ot/base/simplest"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/dkg"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/refresh"
	"github.com/keyzon-technologies/kryptology/pkg/tecdsa/dkls/v2/sign"
	"github.com/keyzon-technologies/kryptology/pkg/zkp/schnorr"
)

const payloadKey = "direct"

var registerCurveTypesOnce sync.Once

// registerCurveTypes registers all concrete curve scalar/point types with the
// gob encoder so that interface values can be serialised correctly.
// It is safe to call multiple times; registration happens exactly once.
func registerCurveTypes() {
	registerCurveTypesOnce.Do(func() {
		gob.Register(&curves.ScalarK256{})
		gob.Register(&curves.PointK256{})
		gob.Register(&curves.ScalarP256{})
		gob.Register(&curves.PointP256{})
	})
}

func checkVersion(version uint) error {
	if version != Version2 {
		return errors.Errorf("DKLS19 v2: unsupported version %d (expected %d)", version, Version2)
	}
	return nil
}

func newMsg(proto, round string, payload []byte, version uint) *protocol.Message {
	return &protocol.Message{
		Protocol: proto,
		Version:  version,
		Payloads: map[string][]byte{payloadKey: payload},
		Metadata: map[string]string{"round": round},
	}
}

func gobEncode(v interface{}) ([]byte, error) {
	registerCurveTypes()
	buf := bytes.NewBuffer([]byte{})
	if err := gob.NewEncoder(buf).Encode(v); err != nil {
		return nil, errors.WithStack(err)
	}
	return buf.Bytes(), nil
}

func gobDecode(data []byte, v interface{}) error {
	if data == nil {
		return errors.New("DKLS19: nil message payload")
	}
	registerCurveTypes()
	return errors.WithStack(gob.NewDecoder(bytes.NewBuffer(data)).Decode(v))
}

// ── DKG round serializers ─────────────────────────────────────────────────────

func encodeDkgRound1Output(seed [simplest.DigestSize]byte, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(&seed)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "1", b, version), nil
}

func decodeDkgRound1Output(m *protocol.Message) ([simplest.DigestSize]byte, error) {
	if err := checkVersion(m.Version); err != nil {
		return [simplest.DigestSize]byte{}, err
	}
	var out [simplest.DigestSize]byte
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeDkgRound2Output(r *dkg.Round2Output, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(r)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "2", b, version), nil
}

func decodeDkgRound2Output(m *protocol.Message) (*dkg.Round2Output, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(dkg.Round2Output)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeDkgRound3Output(proof *schnorr.Proof, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(proof)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "3", b, version), nil
}

func decodeDkgRound3Output(m *protocol.Message) (*schnorr.Proof, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(schnorr.Proof)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeDkgRound4Output(proof *schnorr.Proof, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(proof)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "4", b, version), nil
}

func decodeDkgRound4Output(m *protocol.Message) (*schnorr.Proof, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(schnorr.Proof)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeDkgRound5Output(proof *schnorr.Proof, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(proof)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "5", b, version), nil
}

func decodeDkgRound5Output(m *protocol.Message) (*schnorr.Proof, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(schnorr.Proof)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeDkgRound6Output(choices []simplest.ReceiversMaskedChoices, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(choices)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "6", b, version), nil
}

func decodeDkgRound6Output(m *protocol.Message) ([]simplest.ReceiversMaskedChoices, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.ReceiversMaskedChoices
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeDkgRound7Output(challenges []simplest.OtChallenge, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(challenges)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "7", b, version), nil
}

func decodeDkgRound7Output(m *protocol.Message) ([]simplest.OtChallenge, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.OtChallenge
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeDkgRound8Output(responses []simplest.OtChallengeResponse, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(responses)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "8", b, version), nil
}

func decodeDkgRound8Output(m *protocol.Message) ([]simplest.OtChallengeResponse, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.OtChallengeResponse
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeDkgRound9Output(openings []simplest.ChallengeOpening, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(openings)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "9", b, version), nil
}

func decodeDkgRound9Output(m *protocol.Message) ([]simplest.ChallengeOpening, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.ChallengeOpening
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

// ── DKG output (public API used by Result()) ──────────────────────────────────

// EncodeAliceDkgOutput serialises Alice's DKG output into a protocol.Message.
func EncodeAliceDkgOutput(out *dkg.AliceOutput, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(out)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "alice-output", b, version), nil
}

// EncodeBobDkgOutput serialises Bob's DKG output into a protocol.Message.
func EncodeBobDkgOutput(out *dkg.BobOutput, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(out)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Dkg, "bob-output", b, version), nil
}

// DecodeAliceDkgResult decodes Alice's DKG output from a protocol.Message.
func DecodeAliceDkgResult(m *protocol.Message) (*dkg.AliceOutput, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(dkg.AliceOutput)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

// DecodeBobDkgResult decodes Bob's DKG output from a protocol.Message.
func DecodeBobDkgResult(m *protocol.Message) (*dkg.BobOutput, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(dkg.BobOutput)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

// DecodeSignature decodes the ECDSA signature produced by Bob at the end of signing.
func DecodeSignature(m *protocol.Message) (*curves.EcdsaSignature, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(curves.EcdsaSignature)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

// ── Sign round serializers ────────────────────────────────────────────────────

func encodeSignRound1Output(seed [simplest.DigestSize]byte, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(&seed)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Sign, "1", b, version), nil
}

func decodeSignRound1Output(m *protocol.Message) ([simplest.DigestSize]byte, error) {
	if err := checkVersion(m.Version); err != nil {
		return [simplest.DigestSize]byte{}, err
	}
	var out [simplest.DigestSize]byte
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeSignRound2Output(r *sign.SignRound2Output, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(r)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Sign, "2", b, version), nil
}

func decodeSignRound2Output(m *protocol.Message) (*sign.SignRound2Output, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(sign.SignRound2Output)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeSignRound3Output(r *sign.SignRound3Output, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(r)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Sign, "3", b, version), nil
}

func decodeSignRound3Output(m *protocol.Message) (*sign.SignRound3Output, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(sign.SignRound3Output)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeSignature(sig *curves.EcdsaSignature, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(sig)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Sign, "signature", b, version), nil
}

// ── Refresh round serializers ─────────────────────────────────────────────────

func encodeRefreshRound1Output(kA curves.Scalar, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(&kA)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Refresh, "1", b, version), nil
}

func decodeRefreshRound1Output(m *protocol.Message) (curves.Scalar, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	// curves.Scalar is an interface; use pointer-to-interface so gob can
	// resolve the concrete registered type.
	out := new(curves.Scalar)
	return *out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeRefreshRound2Output(r *refresh.RefreshRound2Output, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(r)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Refresh, "2", b, version), nil
}

func decodeRefreshRound2Output(m *protocol.Message) (*refresh.RefreshRound2Output, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	out := new(refresh.RefreshRound2Output)
	return out, gobDecode(m.Payloads[payloadKey], out)
}

func encodeRefreshRound3Output(choices []simplest.ReceiversMaskedChoices, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(choices)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Refresh, "3", b, version), nil
}

func decodeRefreshRound3Output(m *protocol.Message) ([]simplest.ReceiversMaskedChoices, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.ReceiversMaskedChoices
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeRefreshRound4Output(challenges []simplest.OtChallenge, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(challenges)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Refresh, "4", b, version), nil
}

func decodeRefreshRound4Output(m *protocol.Message) ([]simplest.OtChallenge, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.OtChallenge
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeRefreshRound5Output(responses []simplest.OtChallengeResponse, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(responses)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Refresh, "5", b, version), nil
}

func decodeRefreshRound5Output(m *protocol.Message) ([]simplest.OtChallengeResponse, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.OtChallengeResponse
	return out, gobDecode(m.Payloads[payloadKey], &out)
}

func encodeRefreshRound6Output(openings []simplest.ChallengeOpening, version uint) (*protocol.Message, error) {
	if err := checkVersion(version); err != nil {
		return nil, err
	}
	b, err := gobEncode(openings)
	if err != nil {
		return nil, err
	}
	return newMsg(Dkls19Refresh, "6", b, version), nil
}

func decodeRefreshRound6Output(m *protocol.Message) ([]simplest.ChallengeOpening, error) {
	if err := checkVersion(m.Version); err != nil {
		return nil, err
	}
	var out []simplest.ChallengeOpening
	return out, gobDecode(m.Payloads[payloadKey], &out)
}
