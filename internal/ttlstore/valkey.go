package ttlstore

import (
	"context"
	"slices"
	"time"
	"unsafe"

	"github.com/valkey-io/valkey-go"
)

const DefaultCommandTimeout = 5 * time.Second

type ValkeyClient struct {
	valkey.Client
	CommandTimeout time.Duration
}

func (c *ValkeyClient) ctx() (context.Context, context.CancelFunc) {
	timeout := c.CommandTimeout
	if timeout == 0 {
		timeout = DefaultCommandTimeout
	}
	return context.WithTimeout(context.Background(), timeout)
}

func (c *ValkeyClient) Add(key string, val []byte, ttl uint32) error {
	ctx, done := c.ctx()
	defer done()
	return c.Do(
		ctx,
		c.B().Hsetex().Key(key).Ex(int64(ttl)).Fields().Numfields(1).FieldValue().FieldValue(valkey.BinaryString(val), "").Build(),
	).Error()
}

func (c *ValkeyClient) Set(key string, val []byte, ttl uint32) error {
	ctx, done := c.ctx()
	defer done()
	results := c.DoMulti(
		ctx,
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
	ctx, done := c.ctx()
	defer done()
	var page valkey.ScanEntry
	seen := make(map[string]struct{})
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
	ctx, done := c.ctx()
	defer done()
	return c.Do(ctx, c.B().Exists().Key(key).Build()).AsBool()
}

func (c *ValkeyClient) Values(key string) ([][]byte, error) {
	ctx, done := c.ctx()
	defer done()
	values, err := c.Do(ctx, c.B().Hkeys().Key(key).Build()).AsStrSlice()
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
	ctx, done := c.ctx()
	defer done()
	values, err := c.Do(ctx, c.B().Hkeys().Key(key).Build()).ToArray()
	if len(values) == 0 || err != nil {
		return nil, err
	}
	return values[0].AsBytes()
}

func (c *ValkeyClient) Remove(key string, val []byte) error {
	ctx, done := c.ctx()
	defer done()
	return c.Do(ctx, c.B().Hdel().Key(key).Field(valkey.BinaryString(val)).Build()).Error()
}

func (c *ValkeyClient) Delete(key string) error {
	ctx, done := c.ctx()
	defer done()
	return c.Do(ctx, c.B().Del().Key(key).Build()).Error()
}
