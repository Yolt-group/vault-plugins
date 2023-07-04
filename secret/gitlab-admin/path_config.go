package main

import (
	"context"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
	"github.com/xanzy/go-gitlab"
)

const (
	expectedGitlabAPIUserID    string = "expected gitlab_api_user_id"
	expectedGitlabAPITokenName string = "expected gitlab_api_token_name"
	expectedGitlabAPIToken     string = "expected gitlab_api_token"
	expectedGitlabAPIBaseURL   string = "expected gitlab_api_base_url"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of config",
				Required:    true,
			},
			"gitlab_api_user_id": &framework.FieldSchema{
				Type:        framework.TypeInt,
				Description: "Gitlab API user ID of impersonation token",
			},
			"gitlab_api_token_name": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Gitlab API impersonation token name",
			},
			"gitlab_api_token": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "Gitlab API impersonation token with admin rights",
			},
			"gitlab_api_base_url": &framework.FieldSchema{
				Type:        framework.TypeString,
				Default:     "https://git.yolt.io",
				Description: "Gitlab API base url",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathConfigWrite,
			logical.ReadOperation:   b.pathConfigRead,
		},
	}
}

func pathListConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathConfigList,
		},
	}
}

func pathListConfigs(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "configs/?$",
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathConfigList,
		},
	}
}

func (b *backend) pathConfigList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	configs, err := b.configAccessor.list(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(configs), nil
}

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	cfg, err := b.config(ctx, req.Storage, name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config")
	} else if cfg == nil {
		cfg = &configStorageEntry{}
	}

	if rawAPIUserID, ok := d.GetOk("gitlab_api_user_id"); ok {
		cfg.GitlabAPIUserID = rawAPIUserID.(int)
	}
	if cfg.GitlabAPIUserID == 0 {
		return logical.ErrorResponse(expectedGitlabAPIUserID), nil
	}

	if rawAPITokenName, ok := d.GetOk("gitlab_api_token_name"); ok {
		cfg.GitlabAPITokenName = rawAPITokenName.(string)
	}
	if cfg.GitlabAPITokenName == "" {
		return logical.ErrorResponse(expectedGitlabAPITokenName), nil
	}

	if rawAPIToken, ok := d.GetOk("gitlab_api_token"); ok {
		cfg.GitlabAPIToken = rawAPIToken.(string)
	}
	if cfg.GitlabAPIToken == "" {
		return logical.ErrorResponse(expectedGitlabAPIToken), nil
	}

	if rawBaseURL, ok := d.GetOk("gitlab_api_base_url"); ok {
		cfg.GitlabAPIBaseURL = rawBaseURL.(string)
	}
	if cfg.GitlabAPIBaseURL == "" {
		return logical.ErrorResponse(expectedGitlabAPIBaseURL), nil
	}

	clt := gitlab.NewClient(nil, cfg.GitlabAPIToken)
	clt.SetBaseURL(cfg.GitlabAPIBaseURL)

	cfg.GitlabAPITokenID, err = getTokenID(clt, cfg.GitlabAPIUserID, cfg.GitlabAPITokenName)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}

	if err = b.configAccessor.put(ctx, req.Storage, cfg, name); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}

	return nil, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	name := d.Get("name").(string)
	cfg, err := b.config(ctx, req.Storage, name)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config")
	} else if cfg == nil {
		return nil, logical.CodedError(http.StatusNotFound, "no config found")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"gitlab_api_user_id":    cfg.GitlabAPIUserID,
			"gitlab_api_token_id":   cfg.GitlabAPITokenID,
			"gitlab_api_token_name": cfg.GitlabAPITokenName,
			"gitlab_api_token":      "<sensitive>",
			"gitlab_api_base_url":   cfg.GitlabAPIBaseURL,
		},
	}, nil
}

type configStorageEntry struct {
	GitlabAPIUserID    int    `json:"gitlab_api_user_id" structs:"gitlab_api_user_id"`
	GitlabAPITokenID   int    `json:"gitlab_api_token_id" structs:"gitlab_api_token_id"`
	GitlabAPITokenName string `json:"gitlab_api_token_name" structs:"gitlab_api_token_name"`
	GitlabAPIToken     string `json:"gitlab_api_token" structs:"gitlab_api_token"`
	GitlabAPIBaseURL   string `json:"gitlab_api_base_url" structs:"gitlab_api_base_url"`
}
