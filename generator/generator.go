package generator

import (
	"crypto/ecdsa"

	"github.com/anaskhan96/base58check"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type TronWallet struct {
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	Address    string `json:"address"`
}

func GenerateWallet() (TronWallet, error) {
	data := TronWallet{}
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return data, err
	}

	privateKeyBytes := crypto.FromECDSA(privateKey)
	privateKeyHex := hexutil.Encode(privateKeyBytes)

	publicKey := privateKey.Public()
	publicKeyECDSA := publicKey.(*ecdsa.PublicKey)
	publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)
	publicKeyHex := hexutil.Encode(publicKeyBytes)[2:]

	address := crypto.PubkeyToAddress(*publicKeyECDSA).Hex()
	addressHex := "0x41" + address[2:]

	addressBase58, err := base58check.Encode("41", addressHex[4:])
	if err != nil {
		return data, err
	}

	data.PrivateKey = privateKeyHex[2:]
	data.PublicKey = publicKeyHex
	data.Address = addressBase58

	return data, err
}
