package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/go-secure-stdlib/base62"
	"github.com/hashicorp/vault/sdk/database/helper/credsutil"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathIssue(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of role to issue.",
				Required:    true,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathIssueReadUpdate,
			logical.UpdateOperation: b.pathIssueReadUpdate,
		},
	}
}

func (b *backend) pathIssueReadUpdate(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roleName := d.Get("name").(string)
	role, err := b.role(ctx, r.Storage, roleName)
	if err != nil {
		return nil, err
	} else if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q does not exists", roleName)), nil
	}

	cfg, err := b.config(ctx, r.Storage)
	if err != nil {
		return logical.ErrorResponse("could not find config: " + err.Error()), nil
	}

	name := strings.Split(r.DisplayName, "@")[0]
	userID, err := credsutil.GenerateUsername(
		credsutil.DisplayName(name, 34),
		credsutil.RoleName(roleName, 14),
		credsutil.Case(credsutil.Lowercase),
		credsutil.Separator("_"),
		credsutil.MaxLength(60),
	)
	if err != nil {
		return logical.ErrorResponse("could not generate username: " + err.Error()), nil
	}

	password, err := base62.Random(32)
	if err != nil {
		return logical.ErrorResponse("could not generate password: " + err.Error()), nil
	}

	clt := newNexusClient(cfg.NexusURL, cfg.Username, cfg.Password)
	user, err := clt.createUser(userID, password, role.Roles)
	if err != nil {
		return logical.ErrorResponse("failed to create Nexus user: " + err.Error()), nil
	}

	resp := b.Secret(secretTypeNexus).Response(map[string]interface{}{
		"user_id":  user.UserID,
		"password": password,
		"roles":    user.Roles,
		"ttl":      fmt.Sprintf("%s", role.TTL),
	}, map[string]interface{}{
		"user_id":  userID,
		"password": password,
	})

	resp.Secret.TTL = role.TTL
	resp.Secret.MaxTTL = role.MaxTTL

	// Renewable implemented, but we have to implement explicit_max_ttl to make it secure.
	// So for now, just issue non-renewable secrets.
	resp.Secret.Renewable = false

	return resp, nil
}
