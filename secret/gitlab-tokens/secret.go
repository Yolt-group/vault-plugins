package main

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	gitlab "github.com/xanzy/go-gitlab"
)

const secretTypeGitlabToken = "gitlab_token"

func secretGitlabToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeGitlabToken,
		Fields: map[string]*framework.FieldSchema{},
		Renew:  b.secretGitlabTokenRenew,
		Revoke: b.secretGitlabTokenRevoke,
	}
}

func (b *backend) secretGitlabTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	// Gitlab tokens already have a lifetime, and we don't support renewing it
	return nil, nil
}

func (b *backend) secretGitlabTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	userIDRaw, ok := req.Secret.InternalData["gitlab_user_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing user_id in internal data")
	}
	userID := int(userIDRaw.(float64))

	tokenIDRaw, ok := req.Secret.InternalData["gitlab_token_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing token_id in internal data")
	}
	tokenID := int(tokenIDRaw.(float64))

	gitlabConfigRaw, ok := req.Secret.InternalData["gitlab_config"]
	if !ok {
		return nil, fmt.Errorf("secret is missing gitlab_config in internal data")
	}
	gitlabConfig := gitlabConfigRaw.(string)

	cfg, err := b.config(ctx, req.Storage, gitlabConfig)
	if err != nil {
		return nil, fmt.Errorf("could not find config")
	}

	clt, err := gitlab.NewClient(cfg.GitlabAPIToken, gitlab.WithBaseURL(cfg.GitlabAPIBaseURL))
	if err != nil {
		return nil, fmt.Errorf("gitlab client failed")
	}

	if err = revokeToken(clt, userID, tokenID); err != nil {
		return nil, fmt.Errorf("failed to revoke impersonaton token %q for user %d: %s", tokenID, userID, err.Error())
	}

	return &logical.Response{}, nil
}
