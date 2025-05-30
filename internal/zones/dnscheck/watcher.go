package dnscheck

import (
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	"github.com/miekg/dns"
)

type Watcher interface {
	Send(req *dns.Msg, proto string, remoteAddr net.Addr, connState *tls.ConnectionState)
}

type WatcherHub interface {
	Get(watcherId string) Watcher
	IsRegistered(watcherId string) bool
	Register(watcherId string, watcher Watcher) error
	Unregister(watcherId string)
}

type SimpleWatcherHub struct {
	MaxSize int
	m       map[string]Watcher
	mu      sync.RWMutex
}

func (s *SimpleWatcherHub) Get(watcherId string) Watcher {
	s.mu.RLock()
	watcher := s.m[watcherId]
	s.mu.RUnlock()
	return watcher
}

func (s *SimpleWatcherHub) IsRegistered(watcherId string) bool {
	s.mu.RLock()
	_, exists := s.m[watcherId]
	s.mu.RUnlock()
	return exists
}

func (s *SimpleWatcherHub) Register(watcherId string, watcher Watcher) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = make(map[string]Watcher)
	}
	if s.MaxSize > 0 && len(s.m) >= s.MaxSize {
		if _, exists := s.m[watcherId]; !exists {
			return fmt.Errorf("at max size (%v)", len(s.m))
		}
	}
	s.m[watcherId] = watcher
	return nil
}

func (s *SimpleWatcherHub) Unregister(watcherId string) {
	s.mu.Lock()
	delete(s.m, watcherId)
	s.mu.Unlock()
}

func (s *SimpleWatcherHub) Size() int {
	s.mu.RLock()
	size := len(s.m)
	s.mu.RUnlock()
	return size
}
