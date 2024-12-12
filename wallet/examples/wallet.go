//go:build ignore_vet
// +build ignore_vet

package main

import (
	"fmt"

	"github.com/asmogo/gonuts/cashu"
	"github.com/asmogo/gonuts/cashu/nuts/nut04"
	"github.com/asmogo/gonuts/wallet"
)

func main() {
	config := wallet.Config{
		WalletPath:     "./cashu",
		CurrentMintURL: "http://localhost:3338",
	}

	wallet, err := wallet.LoadWallet(config)

	// Mint tokens
	mintQuote, err := wallet.RequestMint(42, wallet.CurrentMint())

	// Check quote state
	quoteState, err := wallet.MintQuoteState(mintQuote.Quote)
	if quoteState.State == nut04.Paid {
		// Mint tokens if invoice paid
		proofs, err := wallet.MintTokens(mintQuote.Quote)
	}

	// Send
	mint := wallet.CurrentMint()
	includeFees := true
	includeDLEQProof := false
	proofsToSend, err := wallet.Send(21, mint, includeFees)
	token, err := cashu.NewTokenV4(proofsToSend, mint, cashu.Sat, includeDLEQProof)
	fmt.Println(token.Serialize())

	// Receive
	receiveToken, err := cashu.DecodeToken("cashuAeyJ0b2tlbiI6W3sibW...")

	swapToTrustedMint := true
	amountReceived, err := wallet.Receive(receiveToken, swapToTrustedMint)

	// Melt (pay invoice)
	meltQuote, err := wallet.RequestMeltQuote("lnbc100n1pja0w9pdqqx...", mint)
	meltResult, err := wallet.Melt(meltQuote.Quote)
}
