package config

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"io/fs"
	"log"
	"os"
	"slices"
	"time"
)

const (
	TicketKeyLifetime = 7 * 24 * time.Hour
	TicketKeyRotation = 24 * time.Hour
)

type ticketKey struct {
	Key     [32]byte
	Created time.Time
}

type tlsConfig struct {
	*tls.Config
	info string
}

type SessionTicketKeyManager struct {
	file    string
	keys    []ticketKey
	configs []tlsConfig
	add     chan tlsConfig
}

func NewSessionTicketKeyManager(file string) (*SessionTicketKeyManager, error) {
	m := &SessionTicketKeyManager{
		file: file,
		add:  make(chan tlsConfig),
	}
	if err := m.load(); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	m.prune()
	if len(m.keys) == 0 {
		m.addNewKey()
		if err := m.save(); err != nil {
			return nil, err
		}
	}
	go func() {
		rotate := time.NewTimer(time.Until(m.keys[0].Created.Add(TicketKeyRotation)))
		for {
			select {
			case <-rotate.C:
				m.addNewKey()
				m.prune()
				m.setAllConfigKeys()
				if err := m.save(); err != nil {
					log.Fatal(err)
				}
				rotate.Reset(time.Until(m.keys[0].Created.Add(TicketKeyRotation)))
			case c := <-m.add:
				m.configs = append(m.configs, c)
				m.setConfigKeys(c)
			}
		}
	}()
	return m, nil
}

func (m *SessionTicketKeyManager) AddConfig(conf *tls.Config, info string) {
	m.add <- tlsConfig{conf, info}
}

func (m *SessionTicketKeyManager) load() error {
	b, err := os.ReadFile(m.file)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, &m.keys)
}

func (m *SessionTicketKeyManager) save() error {
	b, err := json.Marshal(m.keys, jsontext.WithIndent("  "))
	if err != nil {
		return err
	}
	return os.WriteFile(m.file, b, 0600)
}

func (m *SessionTicketKeyManager) addNewKey() {
	var newKey [32]byte
	rand.Read(newKey[:])
	m.keys = slices.Insert(m.keys, 0, ticketKey{newKey, time.Now()})
}

func (m *SessionTicketKeyManager) prune() {
	m.keys = slices.DeleteFunc(m.keys, func(k ticketKey) bool {
		return time.Since(k.Created) >= TicketKeyLifetime
	})
}

func (m *SessionTicketKeyManager) setAllConfigKeys() {
	for _, c := range m.configs {
		m.setConfigKeys(c)
	}
}

func (m *SessionTicketKeyManager) setConfigKeys(c tlsConfig) {
	keys := make([][32]byte, len(m.keys))
	for i, k := range m.keys {
		b, err := hkdf.Key(sha256.New, k.Key[:], nil, c.info, 32)
		if err != nil {
			panic(err)
		}
		keys[i] = [32]byte(b)
	}
	c.SetSessionTicketKeys(keys)
}
