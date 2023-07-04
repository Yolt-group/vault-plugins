package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	gitlab "github.com/xanzy/go-gitlab"
)

// For rotating the gitlab API access token.
func pathRotateToken(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "rotate-token/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of config",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathRotateToken,
		},
	}
}

func (b *backend) pathRotateToken(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	cfg, err := b.config(ctx, req.Storage, name)
	if err != nil {
		return logical.ErrorResponse("could not find config"), nil
	}

	clt, err := gitlab.NewClient(cfg.GitlabAPIToken, gitlab.WithBaseURL(cfg.GitlabAPIBaseURL))
	if err != nil {
		return nil, fmt.Errorf("gitlab client failed")
	}

	token, tokenID, err := createToken(clt, cfg.GitlabAPIUserID, cfg.GitlabAPITokenName)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create impersonation token")
	}

	oldTokenID := cfg.GitlabAPITokenID
	cfg.GitlabAPIToken = token
	cfg.GitlabAPITokenID = tokenID

	entry, err := logical.StorageEntryJSON("config/"+strings.ToLower(name), cfg)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate storage entry")
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}

	if err = revokeToken(clt, cfg.GitlabAPIUserID, oldTokenID); err != nil {
		return nil, errors.Wrapf(err, "failed to revoke impersionation token")
	}

	return &logical.Response{}, nil
}
