// used to finish the DKG setup bysetting the private key into the secrets.json generatedby local DKG.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/certusone/wormhole/node/pkg/tss"
)

var secretkeypath = flag.String("key", "", "path to the secret key PEM file")
var lkgSecrets = flag.String("lkg", "", "path to the LKG secrets json file")

func main() {
	flag.Parse()

	if *lkgSecrets == "" || *secretkeypath == "" {
		flag.PrintDefaults()

		return
	}

	fmt.Println("loading lkg secrets from:" + *lkgSecrets)
	gsbts, err := os.ReadFile(*lkgSecrets)
	if err != nil {
		panic("couldn't load secrets from key generation protocol " + err.Error())
	}
	var gs tss.GuardianStorage
	json.Unmarshal(gsbts, &gs)

	bts, err := os.ReadFile(*secretkeypath)
	if err != nil {
		panic("issue reading secret key file" + err.Error())
	}

	gs.PrivateKey = bts

	secrets, err := json.MarshalIndent(gs, "", "  ")
	if err != nil {
		panic("issue marshalling secrets" + err.Error())
	}

	if err := os.WriteFile(*lkgSecrets, secrets, 0644); err != nil {
		panic("couldn't write to file" + err.Error())
	}
}
