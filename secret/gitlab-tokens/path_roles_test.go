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
		"gitlab_config": "gitlab-prd",
		"scopes":        "api,sudo",
		"ttl":           "5s",
		"max_ttl":       "10s",
	}

	expected := &roleStorageEntry{
		GitlabConfig: "gitlab-prd",
		Scopes:       []string{"api", "sudo"},
		TTL:          5 * time.Second,
		MaxTTL:       10 * time.Second,
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/sudo",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}
	actual, err := b.(*backend).role(context.Background(), storage, "sudo")
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
		"gitlab_config": "gitlab-dev",
		"scopes":        "api,sudo",
		"ttl":           "5s",
		"max_ttl":       "10s",
	}

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/api",
		Storage:   storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/api",
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
		Path:      "roles/api",
		Storage:   storage,
		Data:      nil,
	}

	resp, err = b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatalf("expected error")
	}

	errMessage := "no role found"
	if err.Error() != errMessage {
		t.Fatalf("expected error: %s", errMessage)
	}
}
