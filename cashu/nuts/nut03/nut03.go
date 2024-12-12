// Package nut03 contains structs as defined in [NUT-03]
//
// [NUT-03]: https://github.com/cashubtc/nuts/blob/main/03.md
package nut03

import "github.com/asmogo/gonuts/cashu"

type PostSwapRequest struct {
	Inputs  cashu.Proofs          `json:"inputs"`
	Outputs cashu.BlindedMessages `json:"outputs"`
}

type PostSwapResponse struct {
	Signatures cashu.BlindedSignatures `json:"signatures"`
}
