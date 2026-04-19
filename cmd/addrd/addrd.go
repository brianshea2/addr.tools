package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"

	"github.com/brianshea2/addr.tools/internal/config"
	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/miekg/dns"
)

func keygen(zone string, alg uint8) {
	dnssecProvider, err := dnsutil.GenerateDnssecProvider(dns.CanonicalName(zone), alg, 300)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ds, _ := dnssecProvider.DS()
	privKey, _ := dnssecProvider.PrivKeyBytes()
	fmt.Printf("%s\n%s ;privKey: %s\n", ds, dnssecProvider.SigningKey, base64.StdEncoding.EncodeToString(privKey))
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
