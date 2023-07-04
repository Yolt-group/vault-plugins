package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
)

func TestRole_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"secret_path":               "integration/k8s/pki/admin",
		"secret_path_method":        "POST",
		"secret_data":               map[string]interface{}{"alt_names": "example.com"},
		"secret_type":               "kubernetes",
		"secret_ttl":                "1h",
		"secret_max_ttl":            "4h",
		"bound_pagerduty_schedules": []string{"sre schedule", "devops schedule"},
		"notify_slack_channels":     []string{"#sre-amsterdam", "#standby"},
	}

	expected := &roleStorageEntry{
		SecretPath:              "integration/k8s/pki/admin",
		SecretPathMethod:        "POST",
		SecretData:              map[string]interface{}{"alt_names": "example.com"},
		SecretType:              "kubernetes",
		SecretTTL:               time.Hour,
		SecretMaxTTL:            4 * time.Hour,
		BoundPagerdutySchedules: []string{"sre schedule", "devops schedule"},
		NotifySlackChannels:     []string{"#sre-amsterdam", "#standby"},
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/integration-k8s-pki-admin",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	actual, err := b.role(context.Background(), storage, "integration-k8s-pki-admin")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, actual)
	}
	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("Unexpected role data: expected %#v\n got %#v\n", expected, resp.Data)
	}
}

func TestRole_Delete(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"secret_path":        "integration/k8s/pki/admin",
		"secret_path_method": "POST",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/integration-k8s-pki-admin",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/integration-k8s-pki-admin",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/integration-k8s-pki-admin",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	if resp != nil {
		t.Fatalf("Unexpected resp data: expected nil got %#v\n", resp.Data)
	}
}

func getBackend(t *testing.T) (*backend, logical.Storage) {
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
