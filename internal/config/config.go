package config

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/sha256"
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
	"sync"
	"syscall"
	"time"

	"github.com/brianshea2/addr.tools/internal/dns2json"
	"github.com/brianshea2/addr.tools/internal/dnsutil"
	"github.com/brianshea2/addr.tools/internal/httputil"
	"github.com/brianshea2/addr.tools/internal/netutil"
	"github.com/brianshea2/addr.tools/internal/status"
	"github.com/brianshea2/addr.tools/internal/ttlstore"
	"github.com/brianshea2/addr.tools/internal/zones/challenges"
	"github.com/brianshea2/addr.tools/internal/zones/dnscheck"
	"github.com/brianshea2/addr.tools/internal/zones/dyn"
	"github.com/brianshea2/addr.tools/internal/zones/myaddr"
	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/valkey-io/valkey-go"
	"golang.org/x/time/rate"
)

const (
	MaxDnscheckWatchers          = 100
	MaxDnscheckLargeResponseRate = 10 // per second
)

type Config struct {
	HTTPSocketPath        string
	RequestLogPath        string
	DatabasePath          string
	ValkeyURL             string
	TLSCertPath           string
	TLSKeyPath            string
	TLSTicketKeysPath     string
	QUICMasterSecret      string
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
	var shutdownWaitGroup sync.WaitGroup
	defer func() {
		graceful := make(chan struct{})
		go func() {
			shutdownWaitGroup.Wait()
			close(graceful)
		}()
		select {
		case <-graceful:
		case <-time.After(3 * time.Second):
			log.Print("[warn] graceful shutdown timeout")
		}
	}()

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
	}
	dnsHandler := &dnsutil.LoggingHandler{
		Logger: requestLogger,
		Next:   dns.DefaultServeMux,
	}
	statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
		return []status.Status{
			{Title: "net.ipv4", Value: strconv.FormatUint(dnsHandler.IP4Count(), 10)},
			{Title: "net.ipv6", Value: strconv.FormatUint(dnsHandler.IP6Count(), 10)},
			{Title: "proto.udp", Value: strconv.FormatUint(dnsHandler.UDPCount(), 10)},
			{Title: "proto.tcp", Value: strconv.FormatUint(dnsHandler.TCPCount(), 10)},
			{Title: "proto.tls", Value: strconv.FormatUint(dnsHandler.TLSCount(), 10)},
			{Title: "proto.quic", Value: strconv.FormatUint(dnsHandler.QUICCount(), 10)},
		}
	}))

	// init valkey client
	var valkeyClient valkey.Client
	if len(config.ValkeyURL) > 0 {
		opt, err := valkey.ParseURL(config.ValkeyURL)
		if err == nil {
			valkeyClient, err = valkey.NewClient(opt)
		}
		if err != nil {
			log.Fatal(err)
		}
		defer valkeyClient.Close()
		log.Printf("[info] connected to %v", config.ValkeyURL)
	}

	// init persistent data store
	var persistentStore ttlstore.TtlStore
	if valkeyClient == nil {
		simpleStore := &ttlstore.SimpleTtlStore{}
		go simpleStore.PrunePeriodically(time.Hour)
		if len(config.DatabasePath) > 0 {
			if err := simpleStore.LoadFile(config.DatabasePath); err != nil && !errors.Is(err, fs.ErrNotExist) {
				log.Fatal(err)
			}
			defer func() {
				if err := simpleStore.WriteFile(config.DatabasePath); err != nil {
					log.Printf("[error] %v", err)
				}
			}()
			go func() {
				log.Fatal(simpleStore.WriteFilePeriodically(config.DatabasePath, time.Minute))
			}()
			log.Printf("[info] loaded database, size %v", simpleStore.Size())
		}
		persistentStore = simpleStore
	} else {
		persistentStore = &ttlstore.ValkeyClient{Client: valkeyClient}
	}

	// init temporary challenge record store
	var challengeStore ttlstore.TtlStore
	if valkeyClient == nil {
		simpleStore := &ttlstore.SimpleTtlStore{}
		go simpleStore.PrunePeriodically(time.Minute)
		challengeStore = simpleStore
	} else {
		challengeStore = &ttlstore.Prefixed{
			Store:  &ttlstore.ValkeyClient{Client: valkeyClient},
			Prefix: "challenge:",
		}
	}

	// init and set dnscheck handlers
	if len(config.DnscheckZones) > 0 {
		var ipinfoClient *httputil.IPInfoClient
		if len(config.IPInfoBaseURL) > 0 {
			ipinfoClient = &httputil.IPInfoClient{
				BaseURL:    config.IPInfoBaseURL,
				HttpClient: http.Client{Timeout: time.Second},
			}
		}
		largeResponseLimiter := rate.NewLimiter(rate.Limit(MaxDnscheckLargeResponseRate), MaxDnscheckLargeResponseRate)
		watcherHub := &dnscheck.SimpleWatcherHub{MaxSize: MaxDnscheckWatchers}
		for _, h := range config.DnscheckZones {
			h.DnscheckHandler.IPInfoClient = ipinfoClient
			h.DnscheckHandler.LargeResponseLimiter = largeResponseLimiter
			h.DnscheckHandler.Watchers = watcherHub
			h.DnscheckHandler.Init(ParsePrivateKey(h.PrivateKey))
			dns.Handle(h.DnscheckHandler.Zone, h.DnscheckHandler)
		}
		http.Handle("/watch/{watcher}", dnscheck.NewWebsocketHandler(watcherHub))
		statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
			return []status.Status{{Title: "watchers", Value: strconv.Itoa(watcherHub.Size())}}
		}))
	}

	// init and set challenges handler
	if config.ChallengesZone.SimpleHandler != nil {
		config.ChallengesZone.SimpleHandler.RecordGenerator = &challenges.RecordGenerator{
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
			DataStore: persistentStore,
		}
		config.DynZone.SimpleHandler.Init(ParsePrivateKey(config.DynZone.PrivateKey))
		dns.Handle(config.DynZone.SimpleHandler.Zone, config.DynZone.SimpleHandler)
		http.Handle("/dyn", &dyn.HTTPHandler{
			DataStore: persistentStore,
			Zone:      config.DynZone.SimpleHandler.Zone,
		})
	}

	// init and set myaddr handlers
	if len(config.MyaddrZones) > 0 {
		myaddrDataStore := &ttlstore.Prefixed{Store: persistentStore, Prefix: "myaddr:"}
		myaddrChallengeStore := &ttlstore.Prefixed{Store: challengeStore, Prefix: "myaddr:"}
		for _, h := range config.MyaddrZones {
			h.SimpleHandler.RecordGenerator = &myaddr.RecordGenerator{
				DataStore:      myaddrDataStore,
				ChallengeStore: myaddrChallengeStore,
			}
			h.SimpleHandler.Init(ParsePrivateKey(h.PrivateKey))
			dns.Handle(h.SimpleHandler.Zone, h.SimpleHandler)
		}
		http.Handle("/admin/myaddr", &myaddr.AdminHandler{
			DataStore:      myaddrDataStore,
			ChallengeStore: myaddrChallengeStore,
		})
		http.Handle("/myaddr-reg", &myaddr.RegistrationHandler{
			DataStore:      myaddrDataStore,
			ChallengeStore: myaddrChallengeStore,
			TurnstileClient: &httputil.TurnstileClient{
				Secret:     config.MyaddrTurnstileSecret,
				HttpClient: http.Client{Timeout: 5 * time.Second},
			},
		})
		http.Handle("/myaddr-update", &myaddr.UpdateHandler{
			DataStore:      myaddrDataStore,
			ChallengeStore: myaddrChallengeStore,
		})
	}

	// set dns lookup handler
	if len(config.LookupUpstream) > 0 {
		lookupHandler := &dns2json.LookupHandler{Upstream: config.LookupUpstream}
		http.Handle("/dns/{name}/{type}", lookupHandler)
		statusHandler.Add(status.StatusProviderFunc(func() []status.Status {
			return []status.Status{
				{Title: "cache.hits", Value: strconv.FormatUint(lookupHandler.HitCount(), 10)},
				{Title: "cache.fwds", Value: strconv.FormatUint(lookupHandler.MissCount(), 10)},
				{Title: "cache.size", Value: strconv.Itoa(lookupHandler.CacheSize())},
			}
		}))
	}

	// start dns listeners
	var udpServer *dns.Server
	defer func() {
		shutdownWaitGroup.Go(func() {
			udpServer.Shutdown()
			log.Print("[info] dns udp server shutdown complete")
		})
	}()
	go func() {
		log.Print("[info] starting dns udp listener")
		udpServer = &dns.Server{
			Addr:          ":53",
			Net:           "udp",
			MsgAcceptFunc: dnsutil.MsgAcceptFunc,
			Handler:       dnsHandler,
		}
		err := udpServer.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
		log.Print("[info] stopped dns udp listener")
	}()
	var tcpServer *dns.Server
	defer func() {
		shutdownWaitGroup.Go(func() {
			tcpServer.Shutdown()
			log.Print("[info] dns tcp server shutdown complete")
		})
	}()
	go func() {
		log.Print("[info] starting dns tcp listener")
		tcpServer = &dns.Server{
			Addr:          ":53",
			Net:           "tcp",
			MsgAcceptFunc: dnsutil.MsgAcceptFunc,
			Handler:       dnsHandler,
		}
		err := tcpServer.ListenAndServe()
		if err != nil {
			log.Fatal(err)
		}
		log.Print("[info] stopped dns tcp listener")
	}()
	if len(config.TLSCertPath) > 0 && len(config.TLSKeyPath) > 0 {
		cert, err := tls.LoadX509KeyPair(config.TLSCertPath, config.TLSKeyPath)
		if err != nil {
			log.Fatal(err)
		}
		var ticketKeyMgr *SessionTicketKeyManager
		if len(config.TLSTicketKeysPath) > 0 {
			ticketKeyMgr, err = NewSessionTicketKeyManager(config.TLSTicketKeysPath)
			if err != nil {
				log.Fatal(err)
			}
		}
		var dotServer *dns.Server
		defer func() {
			shutdownWaitGroup.Go(func() {
				dotServer.Shutdown()
				log.Print("[info] dns over tls server shutdown complete")
			})
		}()
		go func() {
			log.Print("[info] starting dns over tls listener")
			tlsConfig := &tls.Config{
				NextProtos:   []string{"dot"},
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS12,
				CurvePreferences: []tls.CurveID{
					tls.X25519MLKEM768,
					tls.SecP256r1MLKEM768,
					tls.SecP384r1MLKEM1024,
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
			}
			if ticketKeyMgr != nil {
				ticketKeyMgr.AddConfig(tlsConfig, "dot")
			}
			dotServer = &dns.Server{
				Addr:          ":853",
				Net:           "tcp-tls",
				MsgAcceptFunc: dnsutil.MsgAcceptFunc,
				Handler:       dnsHandler,
				TLSConfig:     tlsConfig,
			}
			err := dotServer.ListenAndServe()
			if err != nil {
				log.Fatal(err)
			}
			log.Print("[info] stopped dns over tls listener")
		}()
		var doqServer *dns.Server
		defer func() {
			shutdownWaitGroup.Go(func() {
				doqServer.Shutdown()
				log.Print("[info] dns over quic server shutdown complete")
			})
		}()
		go func() {
			log.Print("[info] starting dns over quic listener")
			tlsConfig := &tls.Config{
				NextProtos:   []string{"doq"},
				Certificates: []tls.Certificate{cert},
				MinVersion:   tls.VersionTLS13,
				CurvePreferences: []tls.CurveID{
					tls.X25519MLKEM768,
					tls.SecP256r1MLKEM768,
					tls.SecP384r1MLKEM1024,
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
				},
			}
			if ticketKeyMgr != nil {
				ticketKeyMgr.AddConfig(tlsConfig, "doq")
			}
			quicConfig := &quic.Config{
				MaxIncomingStreams:    128,
				MaxIncomingUniStreams: -1, // disabled
				Allow0RTT:             true,
			}
			var statelessResetKey *quic.StatelessResetKey
			var tokenGeneratorKey *quic.TokenGeneratorKey
			if len(config.QUICMasterSecret) > 0 {
				secret, err := base64.StdEncoding.DecodeString(config.QUICMasterSecret)
				if err != nil {
					log.Fatal(err)
				}
				key1, err := hkdf.Key(sha256.New, secret, nil, "stateless-reset-key", 32)
				if err != nil {
					log.Fatal(err)
				}
				statelessResetKey = (*quic.StatelessResetKey)(key1)
				key2, err := hkdf.Key(sha256.New, secret, nil, "token-generator-key", 32)
				if err != nil {
					log.Fatal(err)
				}
				tokenGeneratorKey = (*quic.TokenGeneratorKey)(key2)
			}
			udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: 853})
			if err != nil {
				log.Fatal(err)
			}
			retryLimiter := rate.NewLimiter(rate.Limit(100), 100)
			quicTransport := &quic.Transport{
				Conn:                udpConn,
				StatelessResetKey:   statelessResetKey,
				TokenGeneratorKey:   tokenGeneratorKey,
				VerifySourceAddress: func(_ net.Addr) bool { return !retryLimiter.Allow() },
			}
			quicListener, err := quicTransport.ListenEarly(tlsConfig, quicConfig)
			if err != nil {
				log.Fatal(err)
			}
			doqServer = &dns.Server{
				Listener:      netutil.NewQUICStreamListener(quicListener),
				MaxTCPQueries: 1, // max requests per quic stream
				MsgAcceptFunc: dnsutil.MsgAcceptFunc,
				Handler:       dnsHandler,
			}
			err = doqServer.ActivateAndServe()
			if err != nil {
				log.Fatal(err)
			}
			log.Print("[info] stopped dns over quic listener")
		}()
	}

	// start http socket listener
	if len(config.HTTPSocketPath) > 0 {
		var httpServer *http.Server
		defer func() {
			shutdownWaitGroup.Go(func() {
				httpServer.Shutdown(context.Background())
				log.Print("[info] http server shutdown complete")
			})
		}()
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
			httpServer = new(http.Server)
			err = httpServer.Serve(ln)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Fatal(err)
			}
			log.Print("[info] stopped http socket listener")
		}()
	}

	// goroutines are go-ing, wait
	terminate := make(chan os.Signal, 1)
	signal.Notify(terminate, syscall.SIGINT, syscall.SIGTERM)
	<-terminate
}
