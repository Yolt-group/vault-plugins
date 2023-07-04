package main

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathsRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Required. Name of the role.",
					Required:    true,
				},
				"gitlab_config": &framework.FieldSchema{
					Type:        framework.TypeString,
					Description: "Name of the gitlab config.",
					Required:    true,
				},
				"user_id": &framework.FieldSchema{
					Type:        framework.TypeInt,
					Description: `The Gitlab user for which impersonation token is created. If not set, the authenticated user is taken.`,
				},
				"scopes": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Default:     "api",
					Description: `Required. Sets scopes of the Gitlab tokens (for example "api" and "sudo").`,
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: `Default duration in seconds after which the issued token should expire.`,
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Description: `Max duration in seconds after which the issued token should expire.`,
				},
			},
			ExistenceCheck: b.pathRoleExistenceCheck,
			Callbacks: map[logical.Operation]framework.OperationFunc{
				logical.DeleteOperation: b.pathRoleDelete,
				logical.ReadOperation:   b.pathRoleRead,
				logical.CreateOperation: b.pathRoleCreateUpdate,
				logical.UpdateOperation: b.pathRoleCreateUpdate,
			},
		},
	}
}

func pathListRole(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "role/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
	}
}

func pathListRoles(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "roles/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathRoleList,
		},
	}
}

func (b *backend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *backend) pathRoleList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roles, err := b.roleAccessor.list(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

func (b *backend) pathRoleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		return nil, logical.CodedError(http.StatusNotFound, "no role found")
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"name":          name,
			"gitlab_config": role.GitlabConfig,
			"scopes":        role.Scopes,
			"user_id":       role.UserID,
			"ttl":           role.TTL / time.Second,
			"max_ttl":       role.MaxTTL / time.Second,
		},
	}

	return resp, nil
}

func (b *backend) pathRoleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	if err := b.roleAccessor.delete(ctx, req.Storage, name); err != nil {
		return nil, err
	}

	return nil, nil
}

func (b *backend) pathRoleCreateUpdate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if role == nil && req.Operation == logical.CreateOperation {
		role = &roleStorageEntry{}
	} else if role == nil {
		return nil, fmt.Errorf("role entry not found during update operation")
	}

	if gitlabConfigRaw, ok := d.GetOk("gitlab_config"); ok {
		role.GitlabConfig = gitlabConfigRaw.(string)
	} else {
		return logical.ErrorResponse("missing gitlab_config"), nil
	}

	if tokenTTLRaw, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Second * time.Duration(tokenTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.TTL = time.Second * time.Duration(d.Get("ttl").(int))
	}

	if tokenMaxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Second * time.Duration(tokenMaxTTLRaw.(int))
	} else if req.Operation == logical.CreateOperation {
		role.MaxTTL = time.Second * time.Duration(d.Get("max_ttl").(int))
	}

	var resp *logical.Response
	if role.MaxTTL > b.System().MaxLeaseTTL() {
		resp = &logical.Response{}
		role.MaxTTL = b.System().MaxLeaseTTL()
		resp.AddWarning("max_ttl is greater than the system or backend mount's maximum TTL value; issued tokens' max TTL value will be truncated")
	}

	// Check that the TTL value provided is less than the MaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.MaxTTL > time.Duration(0) && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl should not be greater than max_ttl"), nil
	}

	if userIDRaw, ok := d.GetOk("user_id"); ok {
		role.UserID = userIDRaw.(int)
	}

	if scopes, ok := d.GetOk("scopes"); ok {
		role.Scopes = scopes.([]string)
	} else {
		return logical.ErrorResponse("missing role scopes"), nil
	}

	if err = b.roleAccessor.put(ctx, req.Storage, role, name); err != nil {
		return nil, err
	}

	return resp, nil
}

type roleStorageEntry struct {
	GitlabConfig string        `json:"gitlab_config"`
	Scopes       []string      `json:"scopes"`
	UserID       int           `json:"user_id"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
}
