# gh-clone-webhooks

[![build](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/build.yaml/badge.svg)](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/build.yaml) 
[![release](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/release.yaml/badge.svg)](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/release.yaml)

> GitHub CLI extension to clone webhooks from one organization's repositories to another. Supports Hashicorp Vault for secrets retrieval.

## Prerequisites
- [GitHub CLI](https://cli.github.com/manual/installation) installed.
- Repositories must be present in both organizations (source and destination).

- For Hashicorp Vault integration, the following environment variables must be set:
  - `VAULT_ADDR`: The server address (including protocol and port) of your Vault server (_ex: https://192.168.0.1:8200_)
  - `VAULT_TOKEN`: The token to connect to your Vault server with.
  - Additionally, the flag `--vault-secret-key`.

## Install

```bash
$ gh extension install mona-actions/gh-clone-webhooks
```

## Usage

```txt
$ gh clone-webhooks [flags]
```

```txt
gh cli extension to clone webhooks from one organization's repositories to another. Supports Hashicorp Vault for secrets retrieval.

Usage:
  gh clone-webhooks [flags]

Flags:
      --confirm                       Auto respond to confirmation prompt.
      --destination-hostname string   Destination GitHub hostname. (default "github.com")
      --destination-org string        Destination organization name
  -h, --help                          help for gh-clone-webhooks
      --ignore-errors                 Proceed regardless of errors.
      --no-cache                      Disable cache for GitHub API requests.
      --source-hostname string        Source GitHub hostname. (default "github.com")
      --source-org string             Source organization name.
      --vault-secret-key string       The key in the Vault secret corresponding to the webhook secret value.
  -v, --version                       version for gh-clone-webhooks
```

## Notes
- Does **NOT** copy enterprise or organizational webhooks.
- Does **NOT** support copying secrets directly from GitHub.

## Fixes To Add
- Add "update or create" logic to webhook creation
- Adjust vault secret retrieval for v1 with role id & mount point (`${MOUNT}/${produit}/${vault_token}`)
- Adjust timing for API calls for scale (1 second delay is too long)
- Add way to define access token (for apps)