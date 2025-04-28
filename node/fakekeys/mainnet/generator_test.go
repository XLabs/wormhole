package playground

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/certusone/wormhole/node/pkg/common"
	"github.com/certusone/wormhole/node/pkg/guardiansigner"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

func createKey(keyIndex int) {
	privateKey, err := ecdsa.GenerateKey(ethcrypto.S256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	// the key created is not determinstic.
	filenmae := keyFile(keyIndex)
	common.WriteArmoredKey(privateKey, "key used for testing over mainnet. do not use in production", filenmae, common.GuardianKeyArmoredBlock, false)
}

func keyFile(keyIndex int) string {
	return fmt.Sprintf("test.mainnet.node_%d.key", keyIndex)
}

func TestMakeKeys(t *testing.T) {
	// create 19 keys for mainnet, in the format expected by the guardian signer.
	for i := range 5 {
		createKey(i)
	}
}

func TestMakePublicKeysFile(t *testing.T) {
	var addresses common.MarshalableAddresses
	// addresses.Unmarshal("test.mainnet.19nodes.addresses")
	for i := range 5 {
		filename := keyFile(i)

		fs, err := guardiansigner.NewFileSigner(context.Background(), false, filename)
		if err != nil {
			panic(err)
		}

		add := ethcrypto.PubkeyToAddress(fs.PublicKey(context.Background()))
		addresses = append(addresses, add)
	}

	fmt.Println(addresses)
	bts := addresses.Marshal()

	os.WriteFile("test.mainnet.19nodes.addresses", bts, 0644)

}
