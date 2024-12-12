//go:build !integration

package wallet

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"reflect"
	"strconv"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/asmogo/gonuts/cashu"
	"github.com/asmogo/gonuts/crypto"
)

func TestCreateBlindedMessages(t *testing.T) {
	keyset := crypto.WalletKeyset{Id: "009a1f293253e41e"}

	seed, _ := hdkeychain.GenerateSeed(16)
	master, _ := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)

	testWallet := &Wallet{masterKey: master}

	tests := []struct {
		wallet *Wallet
		amount uint64
		keyset crypto.WalletKeyset
	}{
		{testWallet, 420, keyset},
		{testWallet, 10000000, keyset},
		{testWallet, 2500, keyset},
	}

	for _, test := range tests {
		var counter uint32 = 0
		split := cashu.AmountSplit(test.amount)
		blindedMessages, _, _, _ := test.wallet.createBlindedMessages(split, test.keyset.Id, &counter)
		amount := blindedMessages.Amount()
		if amount != test.amount {
			t.Errorf("expected '%v' but got '%v' instead", test.amount, amount)
		}

		for _, message := range blindedMessages {
			if message.Id != test.keyset.Id {
				t.Errorf("expected '%v' but got '%v' instead", test.keyset.Id, message.Id)
			}
		}
	}
}

func TestConstructProofs(t *testing.T) {
	signatures := cashu.BlindedSignatures{
		{
			Amount: 2,
			C_:     "02762f5e23574da3527af71a3b5ab4119eb06d2aede26773ceb94c0dd90bd595e3",
			Id:     "00b3e89101cc0ec3",
		},
		{
			Amount: 8,
			C_:     "03996778727cec32bdc22a24432f7ea693e149e264f53d381d88958de8cc907f92",
			Id:     "00b3e89101cc0ec3",
		},
	}

	secrets := []string{
		"11e932dc8645669eb65305114a40fef80147393aa4cd8e01c254ebdd7efa4f62",
		"ac45fddb4dfb70467353e7e5e7c1de031fe784a3fff0c213267010676d1cbae8",
	}
	r_str := []string{
		"6cc59e6effb48d89a56ff7052dc31ef09fc3a531ac1e2236da167fa4b9d008ab",
		"172233d8212522a84a1f6ff5472cabd949c2388f98420c222ef5e1229ac090bd",
	}
	keyset := generateWalletKeyset("mysecretkey", "0/0/0")

	expected := cashu.Proofs{
		{
			Amount: 2,
			Id:     "00b3e89101cc0ec3",
			Secret: "11e932dc8645669eb65305114a40fef80147393aa4cd8e01c254ebdd7efa4f62",
			C:      "03c820e12087bc49d9878e74908fc912359523e5c01086bb0bfe6d1e279e2d268c",
		},
		{
			Amount: 8,
			Id:     "00b3e89101cc0ec3",
			Secret: "ac45fddb4dfb70467353e7e5e7c1de031fe784a3fff0c213267010676d1cbae8",
			C:      "03dbe6457e275a8b131b97134613fe053b48d93e315a75e92541f673f6e0fcc194",
		},
	}

	rs := make([]*secp256k1.PrivateKey, len(r_str))
	for i, r := range r_str {
		key, err := hex.DecodeString(r)
		if err != nil {
			t.Fatal(err)
		}
		rs[i] = secp256k1.PrivKeyFromBytes(key)
	}

	proofs, err := constructProofs(signatures, cashu.BlindedMessages{}, secrets, rs, keyset)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(proofs, expected) {
		t.Errorf("expected '%v' but got '%v' instead", expected, proofs)
	}

}

func TestConstructProofsError(t *testing.T) {
	keyset := generateWalletKeyset("mysecretkey", "0/0/0")

	tests := []struct {
		signatures cashu.BlindedSignatures
		secrets    []string
		r_str      []string
		keyset     *crypto.WalletKeyset
	}{
		{
			signatures: cashu.BlindedSignatures{
				{
					Amount: 2,
					C_:     "02762f5e23574da3527af71a3b5ab4119eb06d2aede26773ceb94c0dd90bd595e3",
					Id:     "00b3e89101cc0ec3",
				},
			},
			secrets: []string{
				"11e932dc8645669eb65305114a40fef80147393aa4cd8e01c254ebdd7efa4f62",
			},
			r_str:  []string{},
			keyset: keyset,
		},

		{signatures: cashu.BlindedSignatures{
			{
				Amount: 2,
				C_:     "11111a",
				Id:     "00b3e89101cc0ec3",
			},
			{
				Amount: 8,
				C_:     "03996778727cec32bdc22a24432f7ea693e1",
				Id:     "00b3e89101cc0ec3",
			},
		},

			secrets: []string{
				"11e932dc8645669eb65305114a40fef80147393aa4cd8e01c254ebdd7efa4f62",
				"ac45fddb4dfb70467353e7e5e7c1de031fe784a3fff0c213267010676d1cbae8",
			},
			r_str: []string{
				"6cc59e6effb48d89a56ff7052dc31ef09fc3a531ac1e2236da167fa4b9d008ab",
				"172233d8212522a84a1f6ff5472cabd949c2388f98420c222ef5e1229ac090bd",
			},
			keyset: keyset,
		},
	}

	for _, test := range tests {
		rs := make([]*secp256k1.PrivateKey, len(test.r_str))
		for i, r := range test.r_str {
			key, err := hex.DecodeString(r)
			if err != nil {
				t.Fatal(err)
			}
			rs[i] = secp256k1.PrivKeyFromBytes(key)
		}

		proofs, err := constructProofs(test.signatures, cashu.BlindedMessages{}, test.secrets, rs, test.keyset)
		if proofs != nil {
			t.Errorf("expected nil proofs but got '%v'", proofs)
		}

		if err == nil {
			t.Error("expected error but got nil")
		}
	}
}

func generateWalletKeyset(seed, derivationPath string) *crypto.WalletKeyset {
	keys := make(map[uint64]*secp256k1.PublicKey, 64)

	for i := 0; i < 64; i++ {
		amount := uint64(math.Pow(2, float64(i)))
		hash := sha256.Sum256([]byte(seed + derivationPath + strconv.FormatUint(amount, 10)))
		_, pubKey := btcec.PrivKeyFromBytes(hash[:])
		keys[amount] = pubKey
	}
	keysetId := crypto.DeriveKeysetId(keys)
	return &crypto.WalletKeyset{Id: keysetId, Unit: "sat", Active: true, PublicKeys: keys}
}
