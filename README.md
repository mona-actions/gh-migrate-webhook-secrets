# gh-migrate-webhook-secrets

[![build](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/build.yaml/badge.svg)](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/build.yaml)
[![release](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/release.yaml/badge.svg)](https://github.com/mona-actions/gh-migrate-webhook-secrets/actions/workflows/release.yaml)

> GitHub CLI extension to migrate webhook secrets. Supports HashiCorp Vault (KV V1 & V2) as the secret storage intermediary.

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

## Install

```bash
$ gh extension install mona-actions/gh-migrate-webhook-secrets
```

## Upgrade
```bash
$ gh extension upgrade migrate-webhook-secrets
```

## Usage

```txt
$ gh migrate-webhook-secrets [flags] [repos-file]
```

```txt
GitHub CLI extension to migrate webhook secrets. Supports HashiCorp Vault (KV V1 & V2) as the secret storage intermediary.

Usage:
  gh migrate-webhook-secrets [flags] [repos-file]

Flags:
      --confirm                       Auto respond to confirmation prompt
      --destination-hostname string   Set destination GitHub hostname (default "github.com")
      --destination-org string        Set destination organization to migrate to
      --destination-token string      Optional token for authentication (uses GitHub CLI built-in authentication)
  -h, --help                          help for gh
      --no-cache                      Disable cache for GitHub API requests
      --read-threads int              Number of threads to process at a time. (default 5)
      --source-hostname string        Set source GitHub hostname (default "github.com")
      --source-org string             Set source organization to migrate from
      --source-token string           Optional token for authentication (uses GitHub CLI built-in authentication)
      --vault-kvv1                    Use Vault KVv1 instead of KVv2
      --vault-mountpoint string       The mount point of the secrets on the Vault server (default "secret")
      --vault-path-keys strings       The key in the webhook URL (ex: <webhook-server>?secret=<vault-path-key>) to use for finding the corresponding secret
      --vault-value-key string        The key in the Vault secret corresponding to the webhook secret value (default "value")
  -v, --version                       version for gh
      --write-threads int             Number of write threads to process at a time. (WARNING: increasing beyond 1 can trigger the secondary rate limit.) (default 1)

```

## Notes
- Does **NOT** copy enterprise or organizational webhooks.
- Does **NOT** support copying secrets directly from GitHub (must use third-party secret storage like HashiCorp Vault)