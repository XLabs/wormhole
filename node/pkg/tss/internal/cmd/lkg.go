package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	engine "github.com/certusone/wormhole/node/pkg/tss"
	"github.com/certusone/wormhole/node/pkg/tss/internal"

	"github.com/yossigi/tss-lib/v2/ecdsa/keygen"
	"github.com/yossigi/tss-lib/v2/tss"
)

var cnfgPath = flag.String("cnfg", "cnfg.example.json", "path to config file in json format used to run the protocol")

func main() {
	flag.Parse()

	if *cnfgPath == "" {
		flag.PrintDefaults()

		return
	}

	f, err := os.ReadFile(*cnfgPath)
	if err != nil {
		fmt.Println("failed to read file, err: ", err)

		return
	}

	cnfg := &DKGConfig{}
	err = json.Unmarshal(f, cnfg)
	if err != nil {
		fmt.Println("failed to unmarshal config, err: ", err)

		return
	}

	Run(cnfg)
}

// make a json file with the following content:
type DKGConfig struct {
	NumParticipants int
	WantedThreshold int // should be non inclusive. That is, if you have n=19,f=6, then threshold=12 (13 guardians needed to sign).

	GuardianSpecifics []GuardianSpecifics
}

type GuardianSpecifics struct {
	Identifier         Identifier
	WhereToSaveSecrets string // where to save the secrets of this guardian.
}
type Identifier struct {
	// Self Signed, CA level cert.
	TlsX509 engine.PEM // PEM Encoded (see certs.go). Note, you must have the private key of this cert later.
}

type dkgPlayer struct {
	*tss.PartyID

	whereToStore string

	//generated from the secretKey.

	// sorted according to theIdToPIDMapping.
	peerCerts []engine.PEM
	selfCert  []byte

	// same for all guardians // generated here.
	loadDistributionKey []byte

	*tss.PeerContext
	*tss.Parameters
	idToPidMapping map[string]*tss.PartyID

	localParty tss.Party

	// communication channels
	out               <-chan tss.Message
	protocolEndOutput <-chan *keygen.LocalPartySaveData
}

func Run(cnfg *DKGConfig) {
	if cnfg == nil {
		panic("config is nil")
	}

	// ensuring the threshold matches what the library expects.
	// (if n=5,f=1 and we want 2f+1 committees, then WantedThreshold should be equal to 2)
	cnfg.WantedThreshold -= 1

	fmt.Println("Setting up player secrets. This might take a while...")
	all, err := setupPlayers(cnfg)
	if err != nil {
		panic(err)
	}

	for _, p := range all {
		if err := p.localParty.Start(); err != nil && err.Cause() != nil {
			panic("keygen failed to start: " + err.Cause().Error())
		}
	}

	fmt.Println("all players generated their secrets. Starting the protocol. This might take several minutes.")
	simulateDKG(all)
}

func mustPassMessage(newMsg tss.Message, keyToParty map[string]tss.Party) {
	bz, routing, err := newMsg.WireBytes()
	if err != nil {
		panic("Couldn't pass message to party. err: " + err.Error())
	}

	// parsedMsg doesn't contain routing, since it assumes this message arrive for this participant from outside.
	// as a result we'll use the routing of the wireByte msgs.
	parsedMsg, err := tss.ParseWireMessage(bz, routing.From, routing.IsBroadcast)
	if err != nil {
		panic("Couldn't pass message to party. err: " + err.Error())
	}

	if routing.IsBroadcast || routing.To == nil {
		for pID, p := range keyToParty {
			if string(routing.From.GetKey()) == pID {
				continue
			}

			mustFeedParty(p, parsedMsg)
		}

		return
	}

	for _, id := range routing.To {
		p := keyToParty[string(id.GetKey())]
		mustFeedParty(p, parsedMsg)
	}
}

func mustFeedParty(p tss.Party, parsedMsg tss.ParsedMessage) {
	if p == nil {
		panic("party is nil")
	}
	if parsedMsg == nil {
		panic("parsedMsg is nil")
	}

	ok, err := p.Update(parsedMsg)
	if err != nil {
		panic("Couldn't pass message to party. err: " + err.Error())
	}

	if !ok {
		panic("Couldn't update party with message")
	}
}

func simulateDKG(all []*dkgPlayer) {
	done := 0

	keyToParty := map[string]tss.Party{}
	for _, player := range all {
		keyToParty[string(player.PartyID.GetKey())] = player.localParty
	}

	guardians := make([]*engine.GuardianStorage, len(all))
keygenLoop:
	for {
		bagOfMessages := make([]tss.Message, 0, len(all))
		for _, player := range all {
			select {
			case newMsg := <-player.out:
				bagOfMessages = append(bagOfMessages, newMsg)

			case m := <-player.protocolEndOutput:
				player.handleKeygenEndMessage(m, guardians)
				done += 1
				fmt.Println(done)

			default: // avoid blockage.
			}

			if done >= len(all) {
				break keygenLoop
			}
		}

		if len(bagOfMessages) > 0 {
			fmt.Println("passing messages to guardians", len(bagOfMessages))
		}
		for _, msg := range bagOfMessages {
			mustPassMessage(msg, keyToParty)
		}
	}

	fmt.Println("All guardians have finished the protocol. Saving the secrets to disk.")

	for i, guardian := range guardians {
		if guardian == nil {
			panic(fmt.Sprintf("error in script. Guardian[%d] is nil", i))
		}

		bts, err := json.MarshalIndent(guardian, "", "  ")
		if err != nil {
			panic("")
		}

		fname := fmt.Sprintf("%s.json", all[i].whereToStore)

		err = os.WriteFile(fname, bts, 0777)
		if err != nil {
			panic("Failed to write to disk")
		}
	}

}

func (cnfg *DKGConfig) find(tlsX509 []byte) *GuardianSpecifics {
	for _, g := range cnfg.GuardianSpecifics {
		if string(g.Identifier.TlsX509) == string(tlsX509) {
			return &g
		}
	}

	return nil
}

func (cnfg *DKGConfig) validate() error {
	if cnfg.NumParticipants < 1 {
		return fmt.Errorf("number of participants should be at least 1")
	}

	if len(cnfg.GuardianSpecifics) != cnfg.NumParticipants {
		return fmt.Errorf("number of guardian identifiers should be equal to number of participants")
	}

	if cnfg.WantedThreshold >= cnfg.NumParticipants-1 {
		return fmt.Errorf("threshold should be less than number of participants")
	}

	return nil
}

func setupPlayers(cnfg *DKGConfig) ([]*dkgPlayer, error) {
	if err := cnfg.validate(); err != nil {
		return nil, err
	}

	loadBalancingKey := make([]byte, 32)
	_, err := rand.Read(loadBalancingKey)
	if err != nil {
		return nil, err
	}

	partyIDS := make(tss.UnSortedPartyIDs, cnfg.NumParticipants)

	for i, dt := range cnfg.GuardianSpecifics {
		crt, err := internal.PemToCert(dt.Identifier.TlsX509)
		if err != nil {
			return nil, err
		}

		if len(crt.DNSNames) == 0 {
			return nil, fmt.Errorf("expected DNS names in the cert")
		}

		partyIDS[i] = &tss.PartyID{
			MessageWrapper_PartyID: &tss.MessageWrapper_PartyID{
				Id:      string(crt.DNSNames[0]),
				Moniker: "",
				Key:     dt.Identifier.TlsX509,
			},
			Index: -1, // not known until sorted
		}
	}

	sortedPIDs := tss.SortPartyIDs(partyIDS)
	idToPID := map[string]*tss.PartyID{}
	for _, pid := range sortedPIDs {
		idToPID[pid.Id] = pid
	}

	all := make([]*dkgPlayer, cnfg.NumParticipants)

	peerCerts := make([]engine.PEM, cnfg.NumParticipants)

	for _, pid := range sortedPIDs {
		peerCerts[pid.Index] = pid.Key

		tmp := make([]byte, 32)
		copy(tmp, loadBalancingKey)

		peerContext := tss.NewPeerContext(sortedPIDs)

		all[pid.Index] = &dkgPlayer{
			PartyID:             pid,
			peerCerts:           peerCerts,
			loadDistributionKey: tmp,
			PeerContext:         peerContext,
			Parameters:          tss.NewParameters(tss.S256(), peerContext, pid, cnfg.NumParticipants, cnfg.WantedThreshold),
			idToPidMapping:      idToPID,

			out:               make(<-chan tss.Message),
			protocolEndOutput: make(<-chan *keygen.LocalPartySaveData),

			whereToStore: cnfg.find(pid.Key).WhereToSaveSecrets,

			localParty: nil,
		}

		all[pid.Index].setNewKeygenHandler()
	}

	return all, nil
}

func createX509Cert(dnsName string) *x509.Certificate {
	// using random serial number
	var serialNumberLimit = new(big.Int).Lsh(big.NewInt(1), 128)

	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		panic(err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{Organization: []string{"tsscomm"}},
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour * 24 * 366 * 40), // valid for > 40 years used for tests...
		BasicConstraintsValid: true,

		DNSNames:    []string{"localhost", dnsName},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	return &tmpl
}

func (player *dkgPlayer) setNewKeygenHandler() {
	n := len(player.peerCerts)
	out := make(chan tss.Message, n*n*2)               // ready for at least n^2 messages.
	endOut := make(chan *keygen.LocalPartySaveData, 1) // ready for at least a single message.

	player.localParty = keygen.NewLocalParty(player.Parameters, out, endOut)
	player.out = out
	player.protocolEndOutput = endOut
}

func (player *dkgPlayer) handleKeygenEndMessage(m *keygen.LocalPartySaveData, guardians []*engine.GuardianStorage) {
	i, err := m.OriginalIndex()
	if err != nil {
		panic(err)
	}

	guardians[i] = &engine.GuardianStorage{
		Self: player.PartyID,

		Guardians: player.PeerContext.IDs(),

		TlsX509:    engine.PEM(player.Id),
		PrivateKey: nil, // each guardian should load this by themselves.

		GuardianCerts: player.peerCerts,

		Threshold:             player.Threshold(),
		SavedSecretParameters: m,
		LoadDistributionKey:   player.loadDistributionKey,
	}
}
