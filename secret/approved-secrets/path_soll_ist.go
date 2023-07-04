package main

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

func pathSollIst(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "soll-ist",
		Fields: map[string]*framework.FieldSchema{
			"bound_requester_role": {
				Type:        framework.TypeString,
				Description: `Roles from Vault token's metadata that are allowed to request. If unset, any role may approve.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathSollIstRead,
		},
	}
}

func (b *backend) pathSollIstRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	roles, err := b.roleAccessor.list(ctx, r.Storage, "")
	if err != nil {
		return nil, err
	}

	data := make(map[string]interface{})
	for _, rname := range roles {
		role, err := b.role(ctx, r.Storage, rname)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read role: %s: ", rname)
		}

		filter := d.Get("bound_requester_role").(string)
		include := filter == ""
		if !include {

			for _, requesterRole := range role.BoundRequesterRoles {
				if filter == requesterRole {
					include = true
					break
				}
			}
		}

		if include {
			data[rname] = map[string]interface{}{
				"name":                   rname,
				"secret_path":            role.SecretPath,
				"secret_path_method":     role.SecretPathMethod,
				"secret_data":            role.SecretData,
				"secret_type":            role.SecretType,
				"secret_required_fields": role.SecretRequiredFields,
				"secret_ttl":             role.SecretTTL / time.Second,
				"secret_max_ttl":         role.SecretMaxTTL / time.Second,
				"exclusive_lease":        role.ExclusiveLease,
				"bound_requester_ids":    role.BoundRequesterIDs,
				"bound_requester_roles":  role.BoundRequesterRoles,
				"bound_approver_ids":     role.BoundApproverIDs,
				"bound_approver_roles":   role.BoundApproverRoles,
				"min_approvers":          role.MinApprovers,
			}
		}
	}

	return &logical.Response{Data: data}, nil
}
