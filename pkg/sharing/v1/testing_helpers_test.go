//
// Copyright Coinbase, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package v1

import (
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"

	"github.com/keyzon-technologies/kryptology/pkg/core/curves"
)

var (
	modulus = new(big.Int).Set(btcec.S256().N)
	field   = curves.NewField(modulus)
)
