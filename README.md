# gh-clone-webhooks

[![build](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/build.yaml/badge.svg)](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/build.yaml) 
[![release](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/release.yaml/badge.svg)](https://github.com/mona-actions/gh-clone-webhooks/actions/workflows/release.yaml)

> GitHub CLI extension to clone webhooks from one organization to another.

## Install

```bash
$ gh extension install mona-actions/gh-clone-webhooks
```

## Usage

```txt
$ gh clone-webhooks [flags]
```

```txt
gh cli extension to clone webhooks from one org to another.

Usage:
  gh-clone-webhooks [flags]

Flags:
      --auto-proceed                  Proceed regardless of errors.
      --confirm                       Auto respond to confirmation prompt.
      --destination-hostname string   Destination GitHub hostname. (default "github.com")
      --destination-org string        Destination organization name
      --disable-cache                 Disable cache for GitHub API requests.
  -h, --help                          help for gh-clone-webhooks
      --source-hostname string        Source GitHub hostname. (default "github.com")
      --source-org string             Source organization name.
  -v, --version                       version for gh-clone-webhooks
```

## Notes
- Does NOT support copying secrets.