package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretTypeApprovedSecretIssue = "approved_secret_issue"

func secretApprovedSecretIssue(b *backend) *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeApprovedSecretIssue,
		Fields: map[string]*framework.FieldSchema{},
		Renew:  b.secretApprovedSecretIssueRenew,
		Revoke: b.secretApprovedSecretIssueRevoke,
	}
}

func (b *backend) secretApprovedSecretIssueRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := logical.ErrorResponse("approved_secret_issue cannot be renewed - request again instead")
	return resp, nil
}

func (b *backend) secretApprovedSecretIssueRevoke(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
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

	err := b.issueAccessor.delete(ctx, r.Storage, roleName, nonce)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to delete issue for role %q with nonce %q: %s", roleName, nonce, err.Error())), nil
	}

	return nil, nil
}
