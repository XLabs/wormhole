package fakekeys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"runtime"

	"github.com/certusone/wormhole/node/pkg/common"
	"github.com/certusone/wormhole/node/pkg/guardiansigner"
)

const num_servers = 19

func LoadMainNetKey(i int) (guardiansigner.GuardianSigner, error) {
	if i < 0 || i > 18 {
		return nil, fmt.Errorf("guardian index must be between 0 and 18")
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("could not grab file due to runtime.Caller(0) failure")
	}

	fname := fmt.Sprintf("test.mainnet.node_%d.key", i)

	keyFile := path.Join(path.Dir(file), "mainnet", fmt.Sprintf("%d-servers", num_servers), fname)
	return guardiansigner.NewFileSigner(context.Background(), false, keyFile)
}

func LoadPublicKeys() (common.MarshalableAddresses, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, errors.New("could not grab file due to runtime.Caller(0) failure")
	}

	publicKeysFile := path.Join(path.Dir(file), "mainnet", fmt.Sprintf("%d-servers", num_servers), "test.mainnet.19nodes.addresses")

	data, err := os.ReadFile(publicKeysFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read public keys file %s: %w", publicKeysFile, err)
	}

	var addresses common.MarshalableAddresses
	if err := addresses.Unmarshal(data); err != nil {
		return nil, fmt.Errorf("failed to unmarshal public keys: %w", err)
	}

	return addresses, nil
}
