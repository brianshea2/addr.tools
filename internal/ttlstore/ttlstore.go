package ttlstore

type TtlStore interface {
	// appends val to any other values associated with key
	Add(key string, val []byte, ttl uint32) error

	// associates val with key, replacing any other values
	Set(key string, val []byte, ttl uint32) error

	// gets all keys starting with prefix
	List(prefix string) (keys []string, err error)

	// checks if key has any non-expired values
	Exists(key string) (exists bool, err error)

	// gets all non-expired values associated with key
	Values(key string) (vals [][]byte, err error)

	// gets the first non-expired value associated with key
	Get(key string) (val []byte, err error)

	// unassociates val with key, leaving any other values
	Remove(key string, val []byte) error

	// deletes all values associated with key
	Delete(key string) error
}

type Prefixed struct {
	Store  TtlStore
	Prefix string
}

func (p *Prefixed) WithPrefix(key string) string {
	return p.Prefix + key
}

func (p *Prefixed) Add(key string, val []byte, ttl uint32) error {
	return p.Store.Add(p.WithPrefix(key), val, ttl)
}

func (p *Prefixed) Set(key string, val []byte, ttl uint32) error {
	return p.Store.Set(p.WithPrefix(key), val, ttl)
}

func (p *Prefixed) List(prefix string) (keys []string, err error) {
	keys, err = p.Store.List(p.WithPrefix(prefix))
	for i, v := range keys {
		keys[i] = v[len(p.Prefix):]
	}
	return
}

func (p *Prefixed) Exists(key string) (exists bool, err error) {
	return p.Store.Exists(p.WithPrefix(key))
}

func (p *Prefixed) Values(key string) (vals [][]byte, err error) {
	return p.Store.Values(p.WithPrefix(key))
}

func (p *Prefixed) Get(key string) (val []byte, err error) {
	return p.Store.Get(p.WithPrefix(key))
}

func (p *Prefixed) Remove(key string, val []byte) error {
	return p.Store.Remove(p.WithPrefix(key), val)
}

func (p *Prefixed) Delete(key string) error {
	return p.Store.Delete(p.WithPrefix(key))
}
