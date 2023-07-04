# vault-plugins

Vault Plugins

A set of HashiCorp Vault plugins:

- Gitlab Runner authentication backend. Allow GitLab runners to authenticate to Vault. Differentiate between protected
  and non-protected runners.
- Approved secrets backend. Hand out high privileged ephemeral secrets only after appropriate approvals are given and 
  audit trail was established. See also [approved-secrets](/secret/approved-secrets/README.md).
- Gitlab admin. Temporarily escalate GitLab user privileges to GitLab admin, after appropriate approvals.
- Gitlab tokens. Create temporary gitlab access tokens from GitLab pipelines.
- Nexus admin. Create temporal admin privileges for a Nexus instance, after appropriate approvals. See also [nexus](/secret/nexus/README.md).
- Pagerduty secrets. Attach elevated privileges to users currently on Pagerduty standby.


# Create config.hcl with your local plugin directory

```
plugin_directory="/home/user/gitlab/sre/vault-plugins/secret/nexus"
```

# Start local Vault in development mode with plugin directory

```
vault server -dev -dev-root-token-id root -config config.hcl
```

# Register/enable plugin

```
vault plugin register -sha256=$(sha256sum nexus | awk '{ print $1 }') secret nexus
vault secrets enable nexus
```
