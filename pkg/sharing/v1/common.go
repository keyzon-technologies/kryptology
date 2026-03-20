//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	kryptology "github.com/keyzon-technologies/kryptology/pkg/core/curves"
)

// ShareVerifier is used to verify secret shares from Feldman or Pedersen VSS
type ShareVerifier = kryptology.EcPoint
