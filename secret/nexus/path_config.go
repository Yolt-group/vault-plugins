package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"nexus_url": {
				Type:        framework.TypeString,
				Default:     "https://127.0.0.1",
				Description: "URL of Nexus server.",
				Required:    true,
			},
			"username": {
				Type:        framework.TypeString,
				Default:     "admin",
				Description: "Nexus username with role nx-admin.",
				Required:    true,
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password for 'username' rights.",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigCreateUpdate,
			logical.UpdateOperation: b.pathConfigCreateUpdate,
			logical.ReadOperation:   b.pathConfigRead,
		},
	}
}

func (b *backend) pathConfigCreateUpdate(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	config, err := b.config(ctx, r.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		config = &configStorageEntry{}
	}

	config.NexusURL = d.Get("nexus_url").(string)
	if config.NexusURL == "" {
		return logical.ErrorResponse("field 'nexus_url' is mandatory"), nil
	}

	config.Username = d.Get("username").(string)
	if config.Username == "" {
		return logical.ErrorResponse("field 'username' is mandatory"), nil
	}

	config.Password = d.Get("password").(string)
	if config.Password == "" {
		return logical.ErrorResponse("field 'password' is mandatory"), nil
	}

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate storage entry")
	}

	if err := r.Storage.Put(ctx, entry); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}

	clt := newNexusClient(config.NexusURL, config.Username, config.Password)
	if err := clt.validate(); err != nil {
		return nil, err
	}

	if err != clt.validate() {
		return logical.ErrorResponse(fmt.Sprintf("failed to validate nexus user: %s", err)), nil
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config")
	} else if cfg == nil {
		return nil, logical.CodedError(http.StatusNotFound, "no config found")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"nexus_url": cfg.NexusURL,
			"username":  cfg.Username,
			"password":  "<sensitive>",
		},
	}, nil
}

type configStorageEntry struct {
	NexusURL string `json:"nexus_url"`
	Username string `json:"username"`
	Password string `json:"password"`
}
