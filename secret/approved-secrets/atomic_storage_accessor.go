package main

import (
	"context"
	"fmt"
	"path"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/logical"
)

type atomicStorageAccessor struct {
	mutex sync.RWMutex
	path  string
}

func newAtomicStorageAccessor(path string) *atomicStorageAccessor {
	return &atomicStorageAccessor{path: path}
}

func (a *atomicStorageAccessor) get(ctx context.Context, s logical.Storage, subkeys ...string) (*logical.StorageEntry, error) {

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	key := a.path
	for _, subkey := range subkeys {
		key = path.Join(key, strings.ToLower(subkey))
	}

	return s.Get(ctx, key)
}

func (a *atomicStorageAccessor) put(ctx context.Context, s logical.Storage, data interface{}, subkeys ...string) error {

	a.mutex.Lock()
	defer a.mutex.Unlock()

	key := a.path
	for _, subkey := range subkeys {
		key = path.Join(key, strings.ToLower(subkey))
	}

	entry, err := logical.StorageEntryJSON(key, data)
	if err != nil {
		return err
	}
	if entry == nil {
		return fmt.Errorf("failed to create storage entry %q", key)
	}

	return s.Put(ctx, entry)
}

func (a *atomicStorageAccessor) list(ctx context.Context, s logical.Storage, subkeys ...string) ([]string, error) {

	a.mutex.RLock()
	defer a.mutex.RUnlock()

	key := a.path
	for _, subkey := range subkeys {
		key = path.Join(key, strings.ToLower(subkey))
	}

	list, err := s.List(ctx, key+"/")
	if err != nil {
		return nil, err
	}

	return list, nil
}

func (a *atomicStorageAccessor) delete(ctx context.Context, s logical.Storage, subkeys ...string) error {

	a.mutex.Lock()
	defer a.mutex.Unlock()

	key := a.path
	for _, subkey := range subkeys {
		key = path.Join(key, strings.ToLower(subkey))
	}

	return s.Delete(ctx, key)
}
