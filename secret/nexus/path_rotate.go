package main

import (
	"context"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

// For rotating config pasword with nx-admin rights
func pathRotateRoot(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-root",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathRotateRoot,
		},
	}
}

func (b *backend) pathRotateRoot(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	password, err := base62.Random(32)
	if err != nil {
		return logical.ErrorResponse("could not generate password: " + err.Error()), nil
	}

	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("could not find config: " + err.Error()), nil
	}

	clt := newNexusClient(cfg.NexusURL, cfg.Username, cfg.Password)
	if err := clt.changePassword(cfg.Username, password); err != nil {
		return logical.ErrorResponse("failed to change password: " + err.Error()), nil
	}

	cfg.Password = password
	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate storage entry")
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}

	return nil, nil
}
