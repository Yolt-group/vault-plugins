package main

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathsRole(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "role/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of role.",
					Required:    true,
				},
				"roles": &framework.FieldSchema{
					Type:        framework.TypeCommaStringSlice,
					Description: "Roles to assign to Nexus user.",
				},
				"ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Default:     "12h",
					Description: "Default duration in seconds before Nexus user is revoked.",
				},
				"max_ttl": &framework.FieldSchema{
					Type:        framework.TypeDurationSecond,
					Default:     "12h",
					Description: "Max duration in seconds before Nexus user is revoked.",
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

	roles, err := b.roleAccessor.list(ctx, req.Storage, "")
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
			"name":    name,
			"roles":   role.Roles,
			"ttl":     role.TTL / time.Second,
			"max_ttl": role.MaxTTL / time.Second,
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

func (b *backend) pathRoleCreateUpdate(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	role, err := b.role(ctx, r.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		role = &roleStorageEntry{}
	}

	if rolesRaw, ok := d.GetOk("roles"); ok {
		role.Roles = rolesRaw.([]string)
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		role.TTL = time.Second * time.Duration(ttlRaw.(int))
	} else {
		return logical.ErrorResponse("Could not parse field 'ttl'"), nil
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Second * time.Duration(maxTTLRaw.(int))
	} else {
		return logical.ErrorResponse("Could not parse field 'max_ttl'"), nil
	}

	// Check that the TTL value provided is less than the MaxTTL.
	// Sanitizing the TTL and MaxTTL is not required now and can be performed
	// at credential issue time.
	if role.MaxTTL > time.Duration(0) && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl should not be greater than max_ttl"), nil
	}

	var resp *logical.Response
	if role.MaxTTL > b.System().MaxLeaseTTL() {
		role.MaxTTL = b.System().MaxLeaseTTL()
		resp = &logical.Response{}
		resp.AddWarning("max_ttl is greater than the system or backend mount's maximum TTL value; max_ttl value is truncated")
	}

	return resp, b.roleAccessor.put(ctx, r.Storage, role, name)
}

type roleStorageEntry struct {
	Roles  []string      `json:"roles"`
	TTL    time.Duration `json:"ttl"`
	MaxTTL time.Duration `json:"max_ttl"`
}
