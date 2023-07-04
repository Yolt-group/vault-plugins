package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/pkg/errors"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"vault_token": {
				Type:        framework.TypeString,
				Description: `Vault token from which an orphaned token for issuing secrets is generated (typically Vault root token). The vault_policies is attached to the orphaned token.`,
				Required:    true,
			},
			"vault_addr": {
				Type:        framework.TypeString,
				Default:     "http://127.0.0.1:8200",
				Description: `Vault address that holds the secrets.`,
			},
			"vault_policies": {
				Type:        framework.TypeCommaStringSlice,
				Default:     "root",
				Description: `Vault policies attached to the created orphaned Vault token.`,
			},
			"identity_template": {
				Type:        framework.TypeString,
				Description: `List of identity template definitions (for example: "{{identity.entity.aliases.auth_plugin_05c79452.name}}"). If not set, alias name of first identity is taken.`,
			},
			"pagerduty_api_endpoint": {
				Type:        framework.TypeString,
				Description: `Address of pagerduty API endpoint.`,
			},
			"pagerduty_api_token": {
				Type:        framework.TypeString,
				Description: `Token for pagerduty API.`,
			},
			"slack_webhook_url": {
				Type:        framework.TypeString,
				Description: `Address of Slack webhook URL to post alerts.`,
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.CreateOperation: b.pathConfigCreateUpdate,
			logical.UpdateOperation: b.pathConfigCreateUpdate,
			logical.ReadOperation:   b.pathConfigRead,
		},
	}
}

func (b *backend) pathConfigCreateUpdate(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	config, err := b.config(ctx, r.Storage)
	if err != nil {
		return nil, err
	} else if config == nil {
		config = &configStorageEntry{}
	}

	config.VaultToken = d.Get("vault_token").(string)

	if vaultPoliciesRaw, ok := d.GetOk("vault_policies"); ok {
		config.VaultPolicies = vaultPoliciesRaw.([]string)
	}

	if vaultAddrRaw, ok := d.GetOk("vault_addr"); ok {
		config.VaultAddr = vaultAddrRaw.(string)
	}

	if identityTemplateRaw, ok := d.GetOk("identity_template"); ok {
		config.IdentityTemplate = identityTemplateRaw.(string)
	}

	if pagerdutyAPIEndpointRaw, ok := d.GetOk("pagerduty_api_endpoint"); ok {
		config.PagerdutyAPIEndpoint = pagerdutyAPIEndpointRaw.(string)
	}

	if pagerdutyAPITokenRaw, ok := d.GetOk("pagerduty_api_token"); ok {
		config.PagerdutyAPIToken = pagerdutyAPITokenRaw.(string)
	}

	if slackWebhookURLRaw, ok := d.GetOk("slack_webhook_url"); ok {
		config.SlackWebhookURL = slackWebhookURLRaw.(string)
	}

	clt, err := newVaultClient(ctx, config.VaultAddr, config.VaultToken)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create Vault client: %s", err)), nil
	}

	data := map[string]interface{}{
		"policies":     config.VaultPolicies,
		"ttl":          "72h",
		"renewable":    true,
		"display_name": "pagerduty-plugin",
		"meta":         map[string]interface{}{"created_by": "pagerduty-plugin"},
	}

	secret, err := clt.Logical().Write("/auth/token/create-orphan", data)
	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("failed to create orphaned Vault token: %s", err)), nil
	}

	config.VaultToken = secret.Auth.ClientToken

	entry, err := logical.StorageEntryJSON("config", config)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to generate storage entry")
	}

	if err := r.Storage.Put(ctx, entry); err != nil {
		return nil, errors.Wrapf(err, "failed to write configuration to storage")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"vault_token": config.VaultToken,
		},
	}, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	cfg, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to get config")
	} else if cfg == nil {
		return nil, logical.CodedError(http.StatusNotFound, "no config found")
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"vault_addr":             cfg.VaultAddr,
			"vault_token":            "<sensitive>",
			"vault_policies":         cfg.VaultPolicies,
			"identity_template":      cfg.IdentityTemplate,
			"pagerduty_api_endpoint": cfg.PagerdutyAPIEndpoint,
			"pagerduty_api_token":    "<sensitive>",
			"slack_webhook_url":      "<sensitive>",
		},
	}, nil
}

type configStorageEntry struct {
	VaultAddr            string   `json:"vault_addr" structs:"vault_addr"`
	VaultToken           string   `json:"vault_token" structs:"vault_token"`
	VaultPolicies        []string `json:"vault_policies" structs:"vault_policies"`
	IdentityTemplate     string   `json:"identity_template" structs:"identity_template"`
	PagerdutyAPIEndpoint string   `json:"pagerduty_api_endpoint" structs:"pagerduty_api_endpoint"`
	PagerdutyAPIToken    string   `json:"pagerduty_api_token" structs:"pagerduty_api_token"`
	SlackWebhookURL      string   `json:"slack_webhook_url" structs:"slack_webhook_url"`
}
