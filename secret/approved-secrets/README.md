# Approved Secrets

* [Problem](#problem)
* [Solution](#solution)
* [Identity](#identity)
* [Vault-Helper](#vault-helper)
  * [secret-list](#vault-helper-secret-list)
  * [secret-request](#vault-helper-secret-request)
  * [secret-approve](#vault-helper-secret-approve)
  * [secret-issue](#vault-helper-secret-issue)
* [API](#approved-secrets-api)
  * [Configure](#configure)
  * [Create/Update Role](#create/update-role)
  * [List Roles](#create/list-roles)
  * [Read Role](#read-role)
  * [Create Request](#create/update-request)
  * [List Requests](#list-requests)
  * [Read Request](#read-request)
  * [Approve Request](#approve-request)
  * [Issue Secret](#issue-secret)

## Problem

We have defined several secret engines for accessing infrastructure components that serve high-privileged secrets. For example:

* PKI client certificates for Kubernetes with organisation set to _system:masters_
* PKI client certificates for Kafka superuser
* Cassandra superuser credentials
* SSH client certificates to bastion for accessing CloudHSM

In production environments, SRE members must access such high-privileged secrets in case of emergencies. An obvious solution is not to include the ACLs in any Vault policies, effectively hiding the ACLs behind Vault’s root token. Root tokens can only be created with a configured number of unseal key shards, solving only part of compliance ruling. Though, in practice root tokens are inadequate and cumbersome in usage, caused by a combination of the following characteristics:

* Root tokens have no TTL
* Root tokens give access to _everything_
* Root tokens are _anonymous_
* Missing audit events for root token creation
* SRE members are often remote on pager duty

## Solution

For a workable solution to access high-privileged secrets, we define the following requirements:

* Approvals by one or more SRE members
* Approvals by a specific group of SRE members only
* No root tokens for issuing high-privileged secrets
* Sufficient audit events with identity

The above requirements can be implemented by a custom secret engine plugin, like in the example below.

```
secret_engine "approved-secrets" {

  enable {
    type = "plugin"
    plugin_name = "approved-secrets-plugin"
  }

  tune {
    description = "Secrets approved by other SRE members"
    default_lease_ttl = "10m"
    max_lease_ttl = "4h"
  }

  path "config" { 
    approval_ttl = "10m"
    vault_token = "s.l.."
    identity_template = "{{identity.entity.aliases.auth_oidc_e266e98a.name}}"
  }

  path "roles/yfb-prd-k8s-admin"
    secret_path = "yfb-prd/k8s-apiserver/issue/admin"
    secret_path_method = "POST"
    secret_data {
      common_name = "{{identity.entity.aliases.auth_oidc_e266e98a.name}}"
    }
    min_approvers = 2
    bound_approver_ids = "some@yolt.com,one@yolt.com"
    bound_approver_roles = "sre,security"
  }
}
```

In the example, the secret defined by _secret_path_ is only issued if the request is approved by CK1 and CK2.

## Identity

The approval system works with Vault's identity secret engine and in particular [implicit entities](https://www.vaultproject.io/docs/secrets/identity/index.html#implicit-entities) that are assigned when a user succesfully logs in. 
At Yolt, when a user logs in with vault-helper for the authentication method _basic-auth-plugin_, the auth plugin creates a new entity. 
That entity is referred to by the [identity_template](https://learn.hashicorp.com/vault/identity-access-management/policy-templating#available-templating-parameters) in a role's configuration.
For example, the identity template `{{identity.entity.aliases.auth_oidc_e266e98a.name}}` refers to the alias name set by the basic-auth-plugin with mount accessor `auth_oidc_e266e98a`. 
If the identity template cannot be resolved, the approved secrets engine returns a permission denied.

By this approach, requesting and approving secrets are secured by the authentication methods. In case of basic-auth-plugin, it piggybacks on the two-factor authentication enforced by our plugin.

## Vault-Helper

##### vault-helper secret-list

```
$ vault-helper -context prd secret-list -filter ^yfb-prd
yfb-prd-cassa-superuser
yfb-prd-k8s-admin
```

##### vault-helper secret-request

```
$ vault-helper -context prd secret-request -role yfb-prd-k8s-admin
bound_approver_ids: [one@yolt.com]
bound_approver_roles: [sre security]
min_approvers: 1
nonce: b325b7c8-25f7-d8ef-5525-b9afb6f19b75
requester_id: some@yolt.com
requester_role: sre
secret_path: yfb-prd/k8s-apiserver/issue/admin
ttl: 15m0s
```

##### vault-helper secret-approve

```
$ vault-helper -context prd secret-approve -role yfb-prd-k8s-admin -nonce b325b7c8-25f7-d8ef-5525-b9afb6f19b75
nonce: fe5b10bd-b309-fefa-d6a1-1e07c5866a0c
requester_id: some@yolt.com
requester_role: sre
bound_approver_ids: [one@yolt.com]
bound_approver_roles: [sre security]
approver_ids: [one@yolt.com]
approver: one@yolt.com
expires_at: 2019-07-29T08:17:10.364885133Z
min_approvers: 1
```

##### vault-helper secret-issue

```
$ vault-helper -context prd secret-issue -format json -role yfb-prd-k8s-admin -nonce b325b7c8-25f7-d8ef-5525-b9afb6f19b75
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIDWDCCAkCgAwIBAgIUK8Sj3WknpxlUtNfu8BtPIT1i8kIwDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAxMTdGVhbTUtazhzLWFwaXNlcnZlcjAeFw0xOTA3MjkwODAx\nMzFaFw0xOTA3MjkwODEyMzBaMC4xFzAVBgNVBAoTDnN5c3RlbTptYXN0ZXJzMRMw\nEQYDVQQDEwphbmRyZWp0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEA2BECZ8GKO3qTOcWDTF9PaPAT+OES1TZaZeDil8ocreIVHCRaxCLIiyaxwpcP\nuA+yyL9JhJPTmmzp/w5T8vs2a5GKv0ZRu5VxOFBOeV+WYjAs4Kszi31E0ceaaUYW\nsdVTzOvH7KFgqmn6zv0EmxOVFvXQZ7hfKYzWN+rZxvwloDaRdoTNi6e4YDOojX3y\n6W/uaGrstOEn91s56ycDI04Z5URKrapjbe5aBhMbIzPB66owuJB+XXOIb5O2IpRf\nXHJgxl1xZ20BwGi88zoloosTDaCybSKfT+F+/fGuDiSoqdRr+TY/svByk91bozAe\nKIxSCBrT4/zMsXxxLJhc9X15IQIDAQABo34wfDAOBgNVHQ8BAf8EBAMCA6gwEwYD\nVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFO9x1JBcTDN83oxXRPmK5GG8gHHE\nMB8GA1UdIwQYMBaAFK8Enen4aTopqq3QPSLh0Pq1KshXMBUGA1UdEQQOMAyCCmFu\nZHJlanRlc3QwDQYJKoZIhvcNAQELBQADggEBAGnIFVR10AVK0ix4HQfYefE/UxQG\nv33QaW0qu3Kf+nQUZdR++j8/5q4TreTvXFRoArbbePa7YlrNCefwqLp3RgSI7bKW\nrcqLLnR9Mq3yPm7zPGP/AXmIAhIXen5Zygph9pOU4sO+U54SQYC4Qa2nRkhLcpjd\nPShasybcAkewb6aTmH254BAur8FPoaIsvPmNb1lqg687YoztLMDlGYc0DfdpKapv\nDm5htoYCiVwdGHpmHROaVimK6gMGg9KLOv9D0AyueQcZLK3MS2piUTt+p6/NWBCw\nlgwFqohluHupb4u9OVjlSYct2VoFg+kL6xGuAi29oiSc7Gosiv2aWfkKGSQ=\n-----END CERTIFICATE-----",
  "expiration": 1564387950,
  "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDTzCCAjegAwIBAgIURWOGKSVxja3tHT/pJ2R15voZc94wDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAxMTdGVhbTUtazhzLWFwaXNlcnZlcjAeFw0xOTA0MjMxNTMx\nMTJaFw0yMDA0MjIxNTMxNDJaMB4xHDAaBgNVBAMTE3RlYW01LWs4cy1hcGlzZXJ2\nZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr3vYjSdQSUWps3YTA\nOqI86Bs0ifaClu833lfydz2O6jHECs8P8ywH7MSc2eDMGaDKWETWsjUFOkQpA99F\ng47CnZT3TGmu8GkAHrhV8bxGGvW3P94T8QbTO/xutIQOrMottcKwRWU0G4wxQbx8\ncfIGXhuGAcrGcwZ77V+aqAIhxGo/AJHk78X7GLUcyUEch1pMGa5FD+W5NyMzNvxw\njK4qKdQq1xpIA3KkQqlbTYR7EPAKe8w5edCqP3SzlFUaAi89pUlXWkaRSchgvU3L\noCpQV0LQLkEiAo5vnR1Vcw7612iQV3D5MlazGxe83wjjL2zcXDyA+raTB2CVi1BH\nobN5AgMBAAGjgYQwgYEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w\nHQYDVR0OBBYEFK8Enen4aTopqq3QPSLh0Pq1KshXMB8GA1UdIwQYMBaAFK8Enen4\naTopqq3QPSLh0Pq1KshXMB4GA1UdEQQXMBWCE3RlYW01LWs4cy1hcGlzZXJ2ZXIw\nDQYJKoZIhvcNAQELBQADggEBAEe22fg4bacQioN57RMeUEDgnFKoba0ylk4ZF3pY\nWvytXgntLYMFdIDysocFm2WQsfgaccLJLY86BeSlZPKbjam/R0iIW5MxvyqWixpc\n9sfRHWxDRMy8YrwgEIImyjqGaRU4ZzBLQpseelLWfHoXDr7BU9I+G95LgtjWGPSO\nkhYVSO4GleWUGrc0yLvSlg5qtRD3xOvSJUKLP7W0VRAH2/vmWZuo2hP4N3uoNsT8\n21msRrjE+juGs2y3+gs6nz3iKI4aKakhTWiNyLvjH/ZrNfkSddLpwaAPqVs1MCCy\nD179WYdSDjpuHnj004Hc99uiz8NRLRBxLPBeJTzGHRVQKyQ=\n-----END CERTIFICATE-----",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIEp...\n-----END RSA PRIVATE KEY-----",
  "private_key_type": "rsa",
  "serial_number": "2b:c4:a3:dd:69:27:a7:19:54:b4:d7:ee:f0:1b:4f:21:3d:62:f2:42"
}
```

## API

The  approved-secrets-plugin supports several API calls explained below.

### Configure 

The approval system works with Vault's identity secret engine and in particular [implicit entities](https://www.vaultproject.io/docs/secrets/identity/index.html#implicit-entities) that are assigned when a user succesfully logs in. At Yolt, this implies that every request or approval is effectively protected with two-factor authentication.

```
$ vault token create -policy <name> 
                     -orphan 
                     -renewable 
                     -ttl 168h 
                     -display-name approved-secrets-plugin
                     -metadata created_by=approved-secrets-plugin
```

The generated token is renewed every minute.

| **Method** | **Path**      | 
| :------ | :--------- |
| `POST` | `approved-secrets/config` |

##### Parameters

* `vault_token` `(string: <required>)` - Vault client token from which an orphaned token for issuing secrets is generated (typically Vault root token).
* `vault_addr` `(string: http://127.0.0.1:8200)` - Vault address that serves the secret.
* `vault_polices` `(list: [root])` - Polices attached to the created orphaned Vault token. 
* `approval_ttl` `(string: 10m)` - Specifies the TTL for the request of the high-privileged secret.

##### Sample Request

```
vault write approved-secrets/config \
   vault_token=s.lJbN4oFDhe52Jhd0EgJpyabc \
   approval_ttl=15m
```

##### Sample Response

```
Key            Value
---            -----
vault_token    s.mb61Fabcq9v8iBIgHKUabcEU
```

### Create/Update Role

The approval system works with [implicit identities](https://www.vaultproject.io/docs/secrets/identity/index.html#implicit-entities) that are assigned when a user succesfully logs in. At Yolt, this implies that every request or approval is effectively protected with two-factor authentication.

| **Method** | **Path**      | 
| :------ | :--------- |
| `POST` | `/approved-secrets/roles/:name` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.
* `secret_path` `(string: <required>`) - The path of the high-privileged secret.
* `secret_path_method` `(string: POST`) - The request method of secret_path (either GET or POST).
* `secret_data` `(string: POST`) - The static input data send to the secret path (requires POST method).
* `identity_template` `(string)` - Identity template definition, for example _{{identity.entity.aliases.auth_plugin_05c79452.name}}_. If not set, alias name of first identity is taken.
* `min_approvers` `(int: 1)` - Minimum number of approvers (>=1).

##### Sample Request

```
vault write approved-secrets/role/yfb-prd-k8s-pki \
   secret_path=yfb-prd/k8s-apiserver/issue/admin \
   secret_path_method=POST \
   secret_data=common_name={{identity.entity.aliases.auth_plugin_05c79452.name}}
   identity_template={{identity.entity.aliases.auth_plugin_05c79452.name}} 
```

### List Roles

| **Method** | **Path**      | 
| :------ | :--------- |
| `LIST` | `/approved-secrets/roles` |

##### Sample Request

```
vault list approved-secrets/roles
```

##### Sample Response

```
Keys
----
app-prd-cassa-superuser
app-prd-k8s-admin
yfb-ext-prd-cassa-superuser
yfb-ext-prd-k8s-admin
yfb-prd-cassa-superuser
yfb-prd-k8s-admin
yfb-sandbox-cassa-superuser
yfb-sandbox-k8s-admin
```

### Read Role

| **Method** | **Path**      | 
| :------ | :--------- |
| `READ` | `/request/:name` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.

##### Sample Request

```
vault read approved-secrets/roles/yfb-prd-k8s-admin
```

##### Sample Response

```
Key                   Value
---                   -----
bound_approver_ids    [some@yolt.com]
bound_approver_roles  [sre security]
identity_template     {{identity.entity.aliases.auth_oidc_e266e98a.name}}
min_approvers         1
name                  yfb-prd-k8s-admin
secret_data           map[common_name:{{identity.entity.aliases.auth_oidc_e266e98a.name}}]
secret_path           yfb-prd/k8s-apiserver/issue/admin
secret_path_method    POST
```

### Create/Update Request

| **Method** | **Path**      | 
| :------ | :--------- |
| `POST` | `/approved-secrets/request/:name` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.

##### Sample Request

```
vault write -f approved-secrets/request/yfb-prd-k8s-admin
```

##### Sample Response

```
Key                   Value
---                   -----
min_approvers         1
nonce                 0fbceb51-aee5-de2c-510f-4c7c12f3318f
requester_id          some@yolt.com
requester_role        sre
secret_path           yfb-prd/k8s-apiserver/issue/admin
ttl                   10m0s
bound_approver_ids    [one@yolt.com]
bound_approver_roles  [sre security]
```

### List Requests

| **Method** | **Path**      | 
| :------ | :--------- |
| `LIST` | `/approved-secrets/request/:name` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.

##### Sample Request

```
vault list -format json approved-secrets/roles
```

##### Sample Response

```
Keys
----
0fbceb51-aee5-de2c-510f-4c7c12f3318f
1ba1a6c6-74b5-d27e-f690-5e87860806b1
8d21d424-abf3-fd71-8df4-978d4e94dac6
ad82d19e-134f-6dbc-3855-1f7bf0b778ab
```

### Read Request

| **Method** | **Path**      | 
| :------ | :--------- |
| `GET` | `/approved-secrets/request/:name/:nonce` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.
* `nonce` `(string: <required>)` - The nonce generated for the request. This is part of the request URL.

##### Sample Request

```
vault read approved-secrets/request/yfb-prd-k8s-admin/0fbceb51-aee5-de2c-510f-4c7c12f3318f
```

##### Sample Response

```
Key                  Value
---                  -----
bound_approver_ids   [some@yolt.com]
bound_approver_roles [sre security]
approver_ids         []
expires_at           2019-07-28T22:22:41.400930363Z
nonce                0fbceb51-aee5-de2c-510f-4c7c12f3318f
requester_id         one@yolt.com

```

### Approve Request

| **Method** | **Path**      | 
| :------ | :--------- |
| `PUT` | `/approved-secrets/approve/:name` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.
* `nonce` `(string: <required>)` - The nonce generated for the request.

##### Sample Request

```
vault write approved-secrets/approve/yfb-prd-k8s-admin \
  nonce=0fbceb51-aee5-de2c-510f-4c7c12f3318f
```

##### Sample Response

```
Key                  Value
---                  -----
approver             one@yolt.com
expires_at           2019-07-29T02:43:06.442917813Z
min_approvers        1
nonce                759b7586-c7bc-b363-089d-fddff99c1ed5
requester_id         some@yolt.com
bound_approver_ids   [one@yolt.com]
bound_approver_roles [sre security]
approver_ids         [one@yolt.com]
```

### Issue Secret

| **Method** | **Path**      | 
| :------ | :--------- |
| `PUT` | `/approved-secrets/issue/:name` |

##### Parameters

* `name` `(string: <required>)`- Specifies the name of the role to create. This is part of the request URL.
* `nonce` `(string: <required>)` - The nonce generated for the request.

##### Sample Request

```
vault write approved-secrets/issue/yfb-prd-k8s-admin \
  nonce=0fbceb51-aee5-de2c-510f-4c7c12f3318f
```

##### Sample Response

```
{
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIDWDCCAkCgAwIBAgIUehft9niwHM529haZ2LMs8swDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAxMTdGVhbTUtazhzLWFwaXNlcnZlcjAeFw0xOTA3MjkwODA0\nNThaFw0xOTA3MjkwODE1NThaMC4xFzAVBgNVBAoTDnN5c3RlbTptYXN0ZXJzMRMw\nEQYDVQQDEwphbmRyZWp0ZXN0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\nAQEAnxANCdPH2nDHtzcNzdstjgK2+i6wPl63OdF2a3DiTGUQ7k9A+DZQLznkzd8j\n52Rxh4FzqN8Gw+wYWQM3m7oBpK0hsIPuZ8r9xCOQnukmqP3CC926IwXjzOuSkpY9\nAKJBifoPbxs7Vt3LBgd6dWfjIVN11Pj7qly4Elxm6RXzf4GuBhOPnMi4bXcKJnhH\nl8Ygp0JMWYctLXkV3ezYZtzNuavX8bqLy7jtTBTL6zinP3FbvrJ5dotCMp1whbld\nPoA2ZqkUvGyBOA4EfVak1W6htwGQW/eb/0t6Ub+Sv/jRDQVIQ4mVCNF0BhbsEsdV\nqjjTZmylWgxfLIWLue8aSf8yhwIDAQABo34wfDAOBgNVHQ8BAf8EBAMCA6gwEwYD\nVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFOEd7mO1u25ud+iTYM2a/67y2XL+\nMB8GA1UdIwQYMBaAFK8Enen4aTopqq3QPSLh0Pq1KshXMBUGA1UdEQQOMAyCCmFu\nZHJlanRlc3QwDQYJKoZIhvcNAQELBQADggEBAKunLQV7TnQPLnyzbFp9UKeLy/Cf\nSJZwOoTP6rEbmHl/GxWlaNefqVdLiozcWTQN+dGlDpuno99Z2EUXbTm68oRm7jgG\ndPDcKfz9XtGnkeIiwQGKT8UVrIZBZ2U/mRyifHygWmSv/Y5co5wtCeGf15rLDVXm\nTCxM/Z+jDG3BEt4jek7HdOETLOrzxXBsS70/k2S8ypGhAdnxrJ9P0bgTRetZOi9K\nZ5CjuHsAZ9sLYj5+fatm0qcKPxNjLeW4MXXaPds/lvuvx8WVhChl/MSlJzlOrgz9\nuDC2vYBdKOozWiuIQs5H84z9B34VbzfN//4nWJ7M9sJXMBCxIdXFQ+I+DOQ=\n-----END CERTIFICATE-----",
  "expiration": 1564388158,
  "issuing_ca": "-----BEGIN CERTIFICATE-----\nMIIDTzCCAjegAwIBAgIURWOGKSVxja3tHT/pJ2R15voZc94wDQYJKoZIhvcNAQEL\nBQAwHjEcMBoGA1UEAxMTdGVhbTUtazhzLWFwaXNlcnZlcjAeFw0xOTA0MjMxNTMx\nMTJaFw0yMDA0MjIxNTMxNDJaMB4xHDAaBgNVBAMTE3RlYW01LWs4cy1hcGlzZXJ2\nZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCr3vYjSdQSUWps3YTA\nOqI86Bs0ifaClu833lfydz2O6jHECs8P8ywH7MSc2eDMGaDKWETWsjUFOkQpA99F\ng47CnZT3TGmu8GkAHrhV8bxGGvW3P94T8QbTO/xutIQOrMottcKwRWU0G4wxQbx8\ncfIGXhuGAcrGcwZ77V+aqAIhxGo/AJHk78X7GLUcyUEch1pMGa5FD+W5NyMzNvxw\njK4qKdQq1xpIA3KkQqlbTYR7EPAKe8w5edCqP3SzlFUaAi89pUlXWkaRSchgvU3L\noCpQV0LQLkEiAo5vnR1Vcw7612iQV3D5MlazGxe83wjjL2zcXDyA+raTB2CVi1BH\nobN5AgMBAAGjgYQwgYEwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB/wQFMAMBAf8w\nHQYDVR0OBBYEFK8Enen4aTopqq3QPSLh0Pq1KshXMB8GA1UdIwQYMBaAFK8Enen4\naTopqq3QPSLh0Pq1KshXMB4GA1UdEQQXMBWCE3RlYW01LWs4cy1hcGlzZXJ2ZXIw\nDQYJKoZIhvcNAQELBQADggEBAEe22fg4bacQioN57RMeUEDgnFKoba0ylk4ZF3pY\nWvytXgntLYMFdIDysocFm2WQsfgaccLJLY86BeSlZPKbjam/R0iIW5MxvyqWixpc\n9sfRHWxDRMy8YrwgEIImyjqGaRU4ZzBLQpseelLWfHoXDr7BU9I+G95LgtjWGPSO\nkhYVSO4GleWUGrc0yLvSlg5qtRD3xOvSJUKLP7W0VRAH2/vmWZuo2hP4N3uoNsT8\n21msRrjE+juGs2y3+gs6nz3iKI4aKakhTWiNyLvjH/ZrNfkSddLpwaAPqVs1MCCy\nD179WYdSDjpuHnj004Hc99uiz8NRLRBxLPBeJTzGHRVQKyQ=\n-----END CERTIFICATE-----",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMII...\n-----END RSA PRIVATE KEY-----",
  "private_key_type": "rsa",
  "serial_number": "7a:17:ed:f6:78:b0:1c:ce:76:f6:16:80:ba:2b:a7:67:62:cc:b3:cb"
}
```

