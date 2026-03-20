// Copyright Keyzon Technologies. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

// Package v2 provides a high-level wrapper around the DKLS19 sign, dkg, and refresh
// protocols, satisfying the protocol.Iterator interface for use in message-passing
// pipelines.  Serialization, versioning, and step routing are handled here.
package v2

import (
	"github.com/keyzon-technologies/kryptology/pkg/core/protocol"
)

const (
	// Dkls19Dkg is the protocol identifier for the DKLS19 DKG.
	Dkls19Dkg = "DKLs19-DKG"

	// Dkls19Sign is the protocol identifier for the DKLS19 signing protocol.
	Dkls19Sign = "DKLs19-Sign"

	// Dkls19Refresh is the protocol identifier for the DKLS19 key-refresh protocol.
	Dkls19Refresh = "DKLs19-Refresh"

	// Version2 is the protocol version tag for all DKLS19 (v2) messages.
	Version2 = 300
)

// protoStepper runs a pre-defined list of protocol steps in order,
// implementing protocol.Iterator via Next().
type protoStepper struct {
	steps []func(input *protocol.Message) (*protocol.Message, error)
	step  int
}

// Next executes the current step and advances the step counter.
// Returns protocol.ErrProtocolFinished when all steps are done.
func (p *protoStepper) Next(input *protocol.Message) (*protocol.Message, error) {
	if p.complete() {
		return nil, protocol.ErrProtocolFinished
	}
	output, err := p.steps[p.step](input)
	if err != nil {
		return nil, err
	}
	p.step++
	return output, nil
}

func (p *protoStepper) complete() bool { return p.step >= len(p.steps) }
