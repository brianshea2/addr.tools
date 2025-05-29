package config

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/brianshea2/addr.tools/internal/dns2json"
	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/status"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/challenges"
	"github.com/brianshea2/addr.tools/internal/zones/cname"
	"github.com/brianshea2/addr.tools/internal/zones/dnscheck"
	"github.com/brianshea2/addr.tools/internal/zones/dyn"
	ipzone "github.com/brianshea2/addr.tools/internal/zones/ip"
	"github.com/brianshea2/addr.tools/internal/zones/myaddr"
	"github.com/miekg/dns"
	"golang.org/x/time/rate"
)

const (
	MaxTemporaryChallenges       = 10000
	MaxChallengesUpdateRate      = 100 // per second
	MaxDnscheckWatchers          = 100
	MaxDnscheckLargeResponseRate = 10 // per second
)

type Config struct {
	HTTPSocketPath        string
	RequestLogPath        string
	DatabasePath          string
	TLSCertPath           string
	TLSKeyPath            string
	ResponseAddrs         dnsutil.IPCollection
	LookupUpstream        string
	IPInfoBaseURL         string
	MyaddrTurnstileSecret string
	DnscheckZones         []struct {
		*dnscheck.DnscheckHandler
		PrivateKey string
	}
	ChallengesZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	DynZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	IPZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	CnameZone struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
	MyaddrZones []struct {
		*dnsutil.SimpleHandler
		PrivateKey string
	}
}

func ParseConfig(path string) *Config {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	var config Config
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		log.Fatal(err)
	}
	return &config
}

func ParsePrivateKey(s string) []byte {
	if len(s) == 0 {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		log.Fatal(err)
	}
	return b
}

func (config *Config) Run() {
	// init status handler, uptime
	statusHandler := new(status.StatusHandler)
	statusHandler.Add(status.NewUptimeProvider())
	dns.Handle("status.", (&dnsutil.SimpleHandler{
		Zone:            "status.",
		Ns:              []string{"invalid."}, // not delegated
		RecordGenerator: statusHandler,
	}).Init(nil))
	// init dns request logger
	var requestLogger *log.Logger
	if len(config.RequestLogPath) > 0 {
		requestLogFile, err := os.OpenFile(config.RequestLogPath, os.O_RDWR|os.O_APPEND|os.O_CREATE, 0666)
		if err != nil {
			log.Fatal(err)
		}
		buffer := bufio.NewWriter(requestLogFile)
		defer buffer.Flush()
		requestLogger = log.New(buffer, "", log.LstdFlags)
	} else {
		requestLogger = log.Default()
	}
	dnsHandler := &dnsutil.LoggingHandler{
		Logger: requestLogger,
		Next:   dns.DefaultServeMux,
	}
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{{Title: "requests", Value: strconv.FormatUint(dnsHandler.RequestCount(), 10)}}
	}))
	// init persistent data store
	persistentStore := &ttlstore.SimpleTtlStore{}
	go persistentStore.PrunePeriodically(time.Hour)
	if len(config.DatabasePath) > 0 {
		if err := persistentStore.LoadFile(config.DatabasePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Fatal(err)
		}
		defer func() {
			if err := persistentStore.WriteFile(config.DatabasePath); err != nil {
				log.Printf("[error] %v", err)
			}
		}()
		go func() {
			log.Fatal(persistentStore.WriteFilePeriodically(config.DatabasePath, time.Minute))
		}()
	}
	http.Handle("/admin/db/{key...}", &ttlstore.AdminHandler{Store: persistentStore})
	// init temporary challenge record store
	challengeStore := &ttlstore.SimpleTtlStore{MaxSize: MaxTemporaryChallenges}
	go challengeStore.PrunePeriodically(time.Minute)
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{{Title: "challenges", Value: strconv.Itoa(challengeStore.Size())}}
	}))
	// init dnscheck watcher hub
	watcherHub := &dnscheck.SimpleWatcherHub{MaxSize: MaxDnscheckWatchers}
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{{Title: "watchers", Value: strconv.Itoa(watcherHub.Size())}}
	}))
	// init ipinfo client
	var ipinfoClient *httputil.IPInfoClient
	if len(config.IPInfoBaseURL) > 0 {
		ipinfoClient = &httputil.IPInfoClient{
			BaseURL:    config.IPInfoBaseURL,
			HttpClient: http.Client{Timeout: time.Second},
		}
	}
	// init and set dnscheck handlers
	largeResponseLimiter := rate.NewLimiter(rate.Limit(MaxDnscheckLargeResponseRate), MaxDnscheckLargeResponseRate)
	for _, h := range config.DnscheckZones {
		h.DnscheckHandler.IPv4 = config.ResponseAddrs.IPv4
		h.DnscheckHandler.IPv6 = config.ResponseAddrs.IPv6
		h.DnscheckHandler.LargeResponseLimiter = largeResponseLimiter
		h.DnscheckHandler.Watchers = watcherHub
		h.DnscheckHandler.IPInfoClient = ipinfoClient
		h.DnscheckHandler.Init(ParsePrivateKey(h.PrivateKey))
		dns.Handle(h.DnscheckHandler.Zone, h.DnscheckHandler)
	}
	http.Handle("/watch/{watcher}", dnscheck.NewWebsocketHandler(watcherHub))
	// init and set challenges handler
	if config.ChallengesZone.SimpleHandler != nil {
		config.ChallengesZone.SimpleHandler.RecordGenerator = &challenges.RecordGenerator{
			IPv4:           config.ResponseAddrs.IPv4,
			IPv6:           config.ResponseAddrs.IPv6,
			ChallengeStore: challengeStore,
		}
		config.ChallengesZone.SimpleHandler.Init(ParsePrivateKey(config.ChallengesZone.PrivateKey))
		dns.Handle(config.ChallengesZone.SimpleHandler.Zone, config.ChallengesZone.SimpleHandler)
		http.Handle("/challenges", &challenges.HTTPHandler{
			ChallengeStore: challengeStore,
			Zone:           config.ChallengesZone.SimpleHandler.Zone,
		})
	}
	// init and set dyn handler
	if config.DynZone.SimpleHandler != nil {
		config.DynZone.SimpleHandler.RecordGenerator = &dyn.RecordGenerator{
			IPv4:      config.ResponseAddrs.IPv4,
			IPv6:      config.ResponseAddrs.IPv6,
			DataStore: persistentStore,
		}
		config.DynZone.SimpleHandler.Init(ParsePrivateKey(config.DynZone.PrivateKey))
		dns.Handle(config.DynZone.SimpleHandler.Zone, config.DynZone.SimpleHandler)
		http.Handle("/dyn", &dyn.HTTPHandler{
			DataStore: persistentStore,
			Zone:      config.DynZone.SimpleHandler.Zone,
		})
	}
	// init and set ip zone handler
	if config.IPZone.SimpleHandler != nil {
		config.IPZone.SimpleHandler.RecordGenerator = &ipzone.RecordGenerator{
			IPv4:           config.ResponseAddrs.IPv4,
			IPv6:           config.ResponseAddrs.IPv6,
			ChallengeStore: challengeStore,
		}
		config.IPZone.SimpleHandler.UpdateHandler = &ipzone.UpdateHandler{
			ChallengeStore: challengeStore,
			UpdateLimiter:  rate.NewLimiter(rate.Limit(MaxChallengesUpdateRate), MaxChallengesUpdateRate),
		}
		config.IPZone.SimpleHandler.Init(ParsePrivateKey(config.IPZone.PrivateKey))
		dns.Handle(config.IPZone.SimpleHandler.Zone, config.IPZone.SimpleHandler)
	}
	// init and set cname zone handler
	if config.CnameZone.SimpleHandler != nil {
		config.CnameZone.SimpleHandler.RecordGenerator = &cname.RecordGenerator{
			IPv4: config.ResponseAddrs.IPv4,
			IPv6: config.ResponseAddrs.IPv6,
		}
		config.CnameZone.SimpleHandler.Init(ParsePrivateKey(config.CnameZone.PrivateKey))
		dns.Handle(config.CnameZone.SimpleHandler.Zone, config.CnameZone.SimpleHandler)
	}
	// init and set myaddr handlers
	for _, h := range config.MyaddrZones {
		h.SimpleHandler.RecordGenerator = &myaddr.RecordGenerator{
			IPv4:           config.ResponseAddrs.IPv4,
			IPv6:           config.ResponseAddrs.IPv6,
			DataStore:      persistentStore,
			ChallengeStore: challengeStore,
			KeyPrefix:      "myaddr:",
		}
		h.SimpleHandler.Init(ParsePrivateKey(h.PrivateKey))
		dns.Handle(h.SimpleHandler.Zone, h.SimpleHandler)
	}
	http.Handle("/admin/myaddr", &myaddr.AdminHandler{
		DataStore:      persistentStore,
		ChallengeStore: challengeStore,
		KeyPrefix:      "myaddr:",
	})
	http.Handle("/myaddr-reg", &myaddr.RegistrationHandler{
		DataStore:      persistentStore,
		ChallengeStore: challengeStore,
		KeyPrefix:      "myaddr:",
		TurnstileClient: &httputil.TurnstileClient{
			Secret:     config.MyaddrTurnstileSecret,
			HttpClient: http.Client{Timeout: 5 * time.Second},
		},
	})
	http.Handle("/myaddr-update", &myaddr.UpdateHandler{
		DataStore:      persistentStore,
		ChallengeStore: challengeStore,
		KeyPrefix:      "myaddr:",
	})
	// set dns lookup handler
	if len(config.LookupUpstream) > 0 {
		http.Handle("/dns/{name}/{type}", &dns2json.LookupHandler{Upstream: config.LookupUpstream})
	}
	// start dns listeners
	var tsigSecrets map[string]string
	if config.IPZone.SimpleHandler != nil {
		tsigSecrets = map[string]string{config.IPZone.SimpleHandler.Zone: ipzone.TsigSecret}
	}
	go func() {
		log.Print("[info] starting dns udp listener")
		log.Fatal((&dns.Server{
			Addr:          ":53",
			Net:           "udp",
			MsgAcceptFunc: dnsutil.MsgAcceptFunc,
			TsigSecret:    tsigSecrets,
			Handler:       dnsHandler,
		}).ListenAndServe())
	}()
	go func() {
		log.Print("[info] starting dns tcp listener")
		log.Fatal((&dns.Server{
			Addr:          ":53",
			Net:           "tcp",
			MsgAcceptFunc: dnsutil.MsgAcceptFunc,
			TsigSecret:    tsigSecrets,
			Handler:       dnsHandler,
		}).ListenAndServe())
	}()
	if len(config.TLSCertPath) > 0 && len(config.TLSKeyPath) > 0 {
		go func() {
			log.Print("[info] starting dns over tls listener")
			cert, err := tls.LoadX509KeyPair(config.TLSCertPath, config.TLSKeyPath)
			if err != nil {
				log.Fatal(err)
			}
			log.Fatal((&dns.Server{
				Addr:          ":853",
				Net:           "tcp-tls",
				MsgAcceptFunc: dnsutil.MsgAcceptFunc,
				TsigSecret:    tsigSecrets,
				Handler:       dnsHandler,
				TLSConfig: &tls.Config{
					NextProtos:   []string{"dot"},
					Certificates: []tls.Certificate{cert},
					MinVersion:   tls.VersionTLS12,
					CurvePreferences: []tls.CurveID{
						tls.X25519,
						tls.CurveP256,
						tls.CurveP384,
					},
					CipherSuites: []uint16{
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
					},
				},
			}).ListenAndServe())
		}()
	}
	// start http socket listener
	if len(config.HTTPSocketPath) > 0 {
		go func() {
			log.Print("[info] starting http socket listener")
			os.Remove(config.HTTPSocketPath)
			ln, err := net.Listen("unix", config.HTTPSocketPath)
			if err != nil {
				log.Fatal(err)
			}
			err = os.Chmod(config.HTTPSocketPath, 0666)
			if err != nil {
				log.Fatal(err)
			}
			log.Fatal(new(http.Server).Serve(ln))
		}()
	}
	// goroutines are go-ing, wait
	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)
	<-terminate
	log.Print("[info] exiting")
}
