package main

import (
	"context"
	"fmt"
	"path"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretTypeApprovedSecretRequest = "approved_secret_request"

func secretApprovedSecretRequest(b *backend) *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeApprovedSecretRequest,
		Fields: map[string]*framework.FieldSchema{},
		Renew:  b.secretApprovedSecretRequestRenew,
		Revoke: b.secretApprovedSecretRequestRevoke,
	}
}

func (b *backend) secretApprovedSecretRequestRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := logical.ErrorResponse("approved_secret_request cannot be renewed - request again instead")
	return resp, nil
}

func (b *backend) secretApprovedSecretRequestRevoke(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleNameRaw := r.Secret.InternalData["name"]
	if roleNameRaw == "" {
		return logical.ErrorResponse("missing role"), nil
	}
	roleName := roleNameRaw.(string)

	nonceRaw := r.Secret.InternalData["nonce"]
	if nonceRaw == "" {
		return logical.ErrorResponse("missing nonce"), nil
	}
	nonce := nonceRaw.(string)

	err := b.requestAccessor.delete(ctx, r.Storage, path.Join(roleName, nonce))
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to delete request for role %q with nonce %q: %s", roleName, nonce, err.Error())), nil
	}

	return nil, nil
}
