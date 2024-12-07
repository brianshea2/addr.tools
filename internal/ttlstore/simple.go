package ttlstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type ValueWithExpiration struct {
	Expires uint32
	Value   []byte
}

type SimpleTtlStore struct {
	MaxSize int
	mu      sync.RWMutex
	m       map[string][]ValueWithExpiration
	size    int
	dirty   bool
}

func (s *SimpleTtlStore) add(key string, val []byte, ttl uint32) error {
	if s.m == nil {
		s.m = make(map[string][]ValueWithExpiration)
	}
	if s.MaxSize > 0 && s.size >= s.MaxSize {
		return fmt.Errorf("at max size (%v)", s.size)
	}
	s.m[key] = append(s.m[key], ValueWithExpiration{uint32(time.Now().Unix()) + ttl, val})
	s.size++
	s.dirty = true
	return nil
}

func (s *SimpleTtlStore) Add(key string, val []byte, ttl uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.add(key, val, ttl)
}

func (s *SimpleTtlStore) Set(key string, val []byte, ttl uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[key] != nil {
		s.size -= len(s.m[key])
		delete(s.m, key)
	}
	return s.add(key, val, ttl)
}

func (s *SimpleTtlStore) List(prefix string) (keys []string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for key := range s.m {
		if strings.HasPrefix(key, prefix) {
			keys = append(keys, key)
		}
	}
	return
}

func (s *SimpleTtlStore) Values(key string) (vals [][]byte) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := uint32(time.Now().Unix())
	for _, r := range s.m[key] {
		if r.Expires > now {
			vals = append(vals, r.Value)
		}
	}
	return
}

func (s *SimpleTtlStore) Get(key string) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := uint32(time.Now().Unix())
	for _, r := range s.m[key] {
		if r.Expires > now {
			return r.Value
		}
	}
	return nil
}

func (s *SimpleTtlStore) Remove(key string, val []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs := s.m[key]
	removed := false
	for i := 0; i < len(rs); {
		if bytes.Equal(rs[i].Value, val) {
			rs = append(rs[:i], rs[i+1:]...)
			s.size--
			removed = true
			continue
		}
		i++
	}
	if removed {
		if len(rs) == 0 {
			delete(s.m, key)
		} else {
			s.m[key] = rs
		}
		s.dirty = true
	}
}

func (s *SimpleTtlStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[key] != nil {
		s.size -= len(s.m[key])
		delete(s.m, key)
		s.dirty = true
	}
}

func (s *SimpleTtlStore) Size() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.size
}

func (s *SimpleTtlStore) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := uint32(time.Now().Unix())
	for key, rs := range s.m {
		pruned := false
		for i := 0; i < len(rs); {
			if rs[i].Expires <= now {
				rs = append(rs[:i], rs[i+1:]...)
				s.size--
				pruned = true
				continue
			}
			i++
		}
		if pruned {
			if len(rs) == 0 {
				delete(s.m, key)
			} else {
				s.m[key] = rs
			}
			s.dirty = true
		}
	}
}

func (s *SimpleTtlStore) PrunePeriodically(interval time.Duration) {
	for {
		time.Sleep(interval)
		s.Prune()
	}
}

func (s *SimpleTtlStore) WriteFile(path string) error {
	dir, file := filepath.Split(path)
	f, err := os.CreateTemp(dir, file)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	s.mu.Lock()
	defer s.mu.Unlock()
	err = enc.Encode(s.m)
	if err1 := f.Close(); err1 != nil && err == nil {
		err = err1
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err == nil {
		s.dirty = false
	} else {
		os.Remove(f.Name())
	}
	return err
}

func (s *SimpleTtlStore) WriteFilePeriodically(path string, interval time.Duration) error {
	for {
		time.Sleep(interval)
		s.mu.RLock()
		dirty := s.dirty
		s.mu.RUnlock()
		if dirty {
			if err := s.WriteFile(path); err != nil {
				return err
			}
		}
	}
}

func (s *SimpleTtlStore) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	var m map[string][]ValueWithExpiration
	if err = json.NewDecoder(f).Decode(&m); err != nil {
		return err
	}
	var size int
	for _, rs := range m {
		size += len(rs)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = m
	s.size = size
	return nil
}
