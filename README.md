# gh-migrate-webhook-secrets

[![build](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/build.yaml/badge.svg)](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/build.yaml) 
[![release](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/release.yaml/badge.svg)](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/release.yaml)

> GitHub CLI extension to migrate webhooks and their secrets. Supports idempotency, cloning from a source org to destination org, and querying HashiCorp Vault for secrets.

## Prerequisites
- [GitHub CLI](https://cli.github.com/manual/installation) installed.
- Repositories must be present in both organizations (source and destination) when cloning (not required when).

- For Hashicorp Vault integration, the following environment variables & flags must be set:
  - Environment Variables:
    - `VAULT_ADDR`: The server address (including protocol and port) of your Vault server (_ex: https://192.168.0.1:8200_)
    - To authenticate with a token:
      - `VAULT_TOKEN`: The token to connect to your Vault server with.
    - To authenticate with Role ID and Secret ID (will take preference if both are provided):
      - `VAULT_ROLE_ID`
      - `VAULT_SECRET_ID`
  - Flags:
    - `--vault-mountpoint`: The mount point of the secrets database on Vault.
    - `--vault-value-key`: The corresponding key for the value of the secret stored.
    - `--vault-kvv1`: If you need to use Vault KVv1, add this switch.

## Install

```bash
$ gh extension install mona-actions/gh-migrate-webhook-secrets
```

## Usage

```txt
$ gh migrate-webhook-secrets [flags]
```

```txt
GitHub CLI extension to migrate webhooks and their secrets. Supports idempotency, cloning from a source org to destination org, and querying HashiCorp Vault for secrets.

Usage:
  gh migrate-webhook-secrets [flags]

Flags:
      --confirm                       Auto respond to confirmation prompt
      --destination-hostname string   Destination GitHub hostname (default "github.com")
      --destination-org string        Destination organization name
  -h, --help                          help for gh
      --ignore-errors                 Proceed regardless of errors
      --no-cache                      Disable cache for GitHub API requests
      --source-hostname string        Source GitHub hostname (default "github.com")
      --source-org string             Source organization name
      --vault-kvv1                    Use Vault KVv1 instead of KVv2
      --vault-mountpoint string       The mount point of the secrets, prefixes the --vault-value-key flag
      --vault-test                    Test Vault connection
      --vault-value-key string        The key in the Vault secret corresponding to the webhook secret value (default "secret")
  -v, --version                       version for gh
```

## Notes
- Does **NOT** copy enterprise or organizational webhooks.
- Does **NOT** support copying secrets directly from GitHub (must use third-party secret storage like HashiCorp Vault)

## Fixes To Add
- [ ] Add "update or create" logic to webhook creation
- [x] Adjust vault secret retrieval for v1 with role id & mount point (`${MOUNT}/${produit}/${vault_token}`)
- [ ] Adjust timing for API calls for scale (1 second delay is too long)
- [ ] Add way to define access token (for apps)
- [ ] Update flags to better match other tooling (gh-migrate-deploy-hooks)
- [ ] Remove requirement for destination org (assume updating instead of cloning)