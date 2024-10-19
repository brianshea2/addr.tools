package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/brianshea2/addr.tools/internal/config"
	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/miekg/dns"
)

func keygen(zone string, alg uint8) {
	now := uint32(time.Now().Unix())
	dnssecProvider, err := dnsutil.GenerateDnssecProvider(
		dns.CanonicalName(zone),
		alg,
		300,
		now-now%86400,
		now-now%86400+31536000, // 1 year
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ds, _ := dnssecProvider.DS()
	privKey, _ := dnssecProvider.PrivKeyBytes()
	fmt.Printf(
		"%s\n%s\n%s ;privKey: %s\n%s ;validity: %d - %d\n",
		ds, dnssecProvider.Ksk, dnssecProvider.Zsk, base64.StdEncoding.EncodeToString(privKey),
		dnssecProvider.KeySig, dnssecProvider.KeySig.Inception, dnssecProvider.KeySig.Expiration,
	)
	os.Exit(0)
}

func main() {
	var keygenAlg uint
	var configPath, keygenZone string
	flag.StringVar(&configPath, "c", "", "configuration `file`")
	flag.StringVar(&keygenZone, "k", "", "generate DNSSEC keys for the specified `zone` and exit")
	flag.UintVar(&keygenAlg, "a", uint(dns.ECDSAP256SHA256), "use `algorithm` when generating DNSSEC keys")
	flag.Parse()
	if len(configPath) == 0 && len(keygenZone) == 0 {
		flag.Usage()
		os.Exit(2)
	}
	if len(keygenZone) > 0 {
		keygen(keygenZone, uint8(keygenAlg))
	}
	// load config, go!
	config := config.ParseConfig(configPath)
	config.Run()
}
