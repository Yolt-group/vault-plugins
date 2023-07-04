package main

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestRole_Read(t *testing.T) {
	b, storage := getBackend(t)

	data := map[string]interface{}{
		"secret_path":          "integration/k8s/pki/admin",
		"secret_path_method":   "POST",
		"secret_data":          map[string]interface{}{"alt_names": "example.com"},
		"secret_ttl":           "1h",
		"secret_max_ttl":       "4h",
		"exclusive_lease":      false,
		"min_approvers":        "2",
		"bound_approver_ids":   "gd40qy,bc12po,po12lk",
		"bound_approver_roles": "sre,security",
	}

	expected := &roleStorageEntry{
		SecretPath:         "integration/k8s/pki/admin",
		SecretPathMethod:   "POST",
		SecretData:         map[string]interface{}{"alt_names": "example.com"},
		SecretTTL:          time.Hour,
		SecretMaxTTL:       4 * time.Hour,
		ExclusiveLease:     false,
		MinApprovers:       2,
		BoundApproverIDs:   []string{"gd40qy", "bc12po", "po12lk"},
		BoundApproverRoles: []string{"sre", "security"},
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
		"min_approvers":      "2",
		"allowed_approvers":  "gd40qy,bc12po,po12lk",
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
