package main

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestConfig_NoGitlabAPIAccessToken(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"gitlab_api_base_url":   "https:git.yolt.io",
		"gitlab_api_user_id":    187,
		"gitlab_api_token_name": "gitlab-tokens-vault-dev",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/gitlab-dev",
		Storage:   storage,
		Data:      data,
	}

	resp, _ := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != expectedGitlabAPIToken {
		t.Fatalf("got unexpected error: %v", resp.Error())
	}
}

func TestConfig_NoGitlabAPIBaseURL(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"gitlab_api_base_url":   "",
		"gitlab_api_user_id":    187,
		"gitlab_api_token_name": "gitlab-tokens-vault-dev",
		"gitlab_api_token":      "XYX",
	}

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/gitlab-dev",
		Storage:   storage,
		Data:      data,
	}

	resp, _ := b.HandleRequest(context.Background(), req)
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error")
	}
	if resp.Error().Error() != expectedGitlabAPIBaseURL {
		t.Fatalf("got unexpected error: %q, expected: %q", resp.Error(), expectedGitlabAPIBaseURL)
	}
}

func getBackend(t *testing.T) (logical.Backend, logical.Storage) {
	defaultLeaseTTLVal := time.Hour * 12
	maxLeaseTTLVal := time.Hour * 24
	b := newBackend()

	config := &logical.BackendConfig{
		Logger: logging.NewVaultLogger(log.Trace),

		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
		StorageView: &logical.InmemStorage{},
	}
	err := b.Setup(context.Background(), config)
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	return b, config.StorageView
}
