package ttlstore

import (
	"context"
	"slices"
	"unsafe"

	"github.com/valkey-io/valkey-go"
)

type ValkeyClient struct {
	valkey.Client
}

func (c *ValkeyClient) Add(key string, val []byte, ttl uint32) error {
	return c.Do(
		context.Background(),
		c.B().Hsetex().Key(key).Ex(int64(ttl)).Fields().Numfields(1).FieldValue().FieldValue(valkey.BinaryString(val), "").Build(),
	).Error()
}

func (c *ValkeyClient) Set(key string, val []byte, ttl uint32) error {
	results := c.DoMulti(
		context.Background(),
		c.B().Multi().Build(),
		c.B().Del().Key(key).Build(),
		c.B().Hsetex().Key(key).Ex(int64(ttl)).Fields().Numfields(1).FieldValue().FieldValue(valkey.BinaryString(val), "").Build(),
		c.B().Exec().Build(),
	)
	for _, result := range results {
		if err := result.Error(); err != nil {
			return err
		}
	}
	return nil
}

func (c *ValkeyClient) List(prefix string) (keys []string, err error) {
	ctx := context.Background()
	seen := make(map[string]struct{})
	var page valkey.ScanEntry
	for {
		page, err = c.Do(ctx, c.B().Scan().Cursor(page.Cursor).Match(prefix+"*").Count(100).Build()).AsScanEntry()
		if err != nil {
			return nil, err
		}
		keys = slices.Grow(keys, len(page.Elements))
		for _, key := range page.Elements {
			if _, exists := seen[key]; exists {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		if page.Cursor == 0 {
			break
		}
	}
	return
}

func (c *ValkeyClient) Exists(key string) (bool, error) {
	return c.Do(context.Background(), c.B().Exists().Key(key).Build()).AsBool()
}

func (c *ValkeyClient) Values(key string) ([][]byte, error) {
	values, err := c.Do(context.Background(), c.B().Hkeys().Key(key).Build()).AsStrSlice()
	if len(values) == 0 || err != nil {
		return nil, err
	}
	out := make([][]byte, 0, len(values))
	for _, v := range values {
		out = append(out, unsafe.Slice(unsafe.StringData(v), len(v)))
	}
	return out, nil
}

func (c *ValkeyClient) Get(key string) ([]byte, error) {
	values, err := c.Do(context.Background(), c.B().Hkeys().Key(key).Build()).ToArray()
	if len(values) == 0 || err != nil {
		return nil, err
	}
	return values[0].AsBytes()
}

func (c *ValkeyClient) Remove(key string, val []byte) error {
	return c.Do(context.Background(), c.B().Hdel().Key(key).Field(valkey.BinaryString(val)).Build()).Error()
}

func (c *ValkeyClient) Delete(key string) error {
	return c.Do(context.Background(), c.B().Del().Key(key).Build()).Error()
}
