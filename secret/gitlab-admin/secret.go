package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/xanzy/go-gitlab"
)

const secretTypeGitlabAdmin = "gitlab_admin"

func secretGitlabToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type:   secretTypeGitlabAdmin,
		Fields: map[string]*framework.FieldSchema{},
		Renew:  b.secretGitlabTokenRenew,
		Revoke: b.secretGitlabTokenRevoke,
	}
}

func (b *backend) secretGitlabTokenRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	resp := logical.ErrorResponse("gitlab tokens cannot be renewed - request new access token instead")
	return resp, nil
}

func (b *backend) secretGitlabTokenRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	userIDRaw, ok := req.Secret.InternalData["user_id"]
	if !ok {
		return nil, fmt.Errorf("secret is missing user_id internal data")
	}
	userID := int(userIDRaw.(float64))

	gitlabConfigRaw, ok := req.Secret.InternalData["gitlab_config"]
	if !ok {
		return nil, fmt.Errorf("secret is missing gitlab_config in internal data")
	}
	gitlabConfig := gitlabConfigRaw.(string)

	cfg, err := b.config(ctx, req.Storage, gitlabConfig)
	if err != nil {
		return nil, fmt.Errorf("could not find config")
	}

	clt := gitlab.NewClient(nil, cfg.GitlabAPIToken)
	clt.SetBaseURL(cfg.GitlabAPIBaseURL)

	opts := &gitlab.ModifyUserOptions{Admin: gitlab.Bool(false)}
	_, _, err = clt.Users.ModifyUser(userID, opts)
	if err != nil {
		return nil, logical.CodedError(http.StatusForbidden, "failed to get Gitlab user %d: "+err.Error())
	}

	return &logical.Response{}, nil
}
