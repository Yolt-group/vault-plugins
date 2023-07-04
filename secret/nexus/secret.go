package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

const secretTypeNexus = "nexus"

func secretNexus(b *backend) *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeNexus,
		Fields: map[string]*framework.FieldSchema{},
		Renew:  b.secretCredsRenew,
		Revoke: b.secretCredsRevoke,
	}
}

func (b *backend) secretCredsRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, errors.New("secret is missing role in internal data")
	}

	role, err := b.role(ctx, req.Storage, roleRaw.(string))
	if err != nil {
		return nil, errors.Errorf("could not find role: %s", roleRaw.(string))
	}

	resp := &logical.Response{Secret: req.Secret}
	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL
	return resp, nil
}

func (b *backend) secretCredsRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	userIDRaw, ok := req.Secret.InternalData["user_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing user_id in internal data")
	}
	userID := userIDRaw.(string)

	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return logical.ErrorResponse("could not find config: " + err.Error()), nil
	}

	clt := newNexusClient(cfg.NexusURL, cfg.Username, cfg.Password)
	if err := clt.validate(); err != nil {
		return nil, err
	}

	if err != clt.deleteUser(userID) {
		return logical.ErrorResponse(fmt.Sprintf("failed to delete nexus user: %s", err)), nil
	}

	return &logical.Response{}, nil
}
