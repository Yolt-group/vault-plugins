package main

import (
	"context"
	"encoding/json"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

func backendFactory(ctx context.Context, c *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, c); err != nil {
		return nil, errors.Wrapf(err, "failed to create factory")
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	configAccessor, roleAccessor *atomicStorageAccessor
}

func newBackend() *backend {
	b := &backend{
		configAccessor: newAtomicStorageAccessor("config"),
		roleAccessor:   newAtomicStorageAccessor("role"),
	}

	b.Backend = &framework.Backend{
		PeriodicFunc: newVaultTokenRenewer(b),
		BackendType:  logical.TypeLogical,
		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathListRole(b),
				pathListRoles(b),
				pathIssue(b),
			},
			pathsRole(b),
		),
	}

	return b
}

func newVaultTokenRenewer(b *backend) func(context.Context, *logical.Request) error {

	backend := b
	return func(ctx context.Context, r *logical.Request) error {

		config, err := backend.config(ctx, r.Storage)
		if err != nil {
			return nil // Ignore errors to avoid secret engine disable failures.
		} else if config == nil {
			return nil // No config, nothing to revoke.
		}

		clt, err := newVaultClient(ctx, config.VaultAddr, config.VaultToken)
		if err != nil {
			return nil // Ignore errors to avoid secret engine disable failures.
		}

		data := map[string]interface{}{
			"increment": "72h",
		}

		_, err = clt.Logical().Write("/auth/token/renew-self", data)
		if err != nil {
			return nil // Ignore errors to avoid secret engine disable failures.
		}

		return nil
	}
}

func (b *backend) role(ctx context.Context, s logical.Storage, name string) (*roleStorageEntry, error) {

	entry, err := b.roleAccessor.get(ctx, s, name)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil // Not found.
	}

	role := &roleStorageEntry{}
	if err := json.Unmarshal(entry.Value, role); err != nil {
		return nil, err
	}

	return role, nil
}

func (b *backend) config(ctx context.Context, s logical.Storage) (*configStorageEntry, error) {

	entry, err := b.configAccessor.get(ctx, s)
	if err != nil {
		return nil, err
	} else if entry == nil {
		return nil, nil // Not found.
	}

	config := &configStorageEntry{}
	if err := json.Unmarshal(entry.Value, config); err != nil {
		return nil, err
	}

	return config, nil
}
