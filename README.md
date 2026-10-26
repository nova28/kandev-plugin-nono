# Nono sandbox provider for Kandev

This repository contains the optional Nono provider. Core command wrapping works without this plugin.

The provider compiles canonical grants for pinned Nono 0.80.0 on Linux amd64. It translates file approval requests and decision replies. It verifies audit event chains and proposes grants from explicitly selected denial records. Kandev owns process launch, operator authority, ceilings, persistence, and cleanup.

## Current status

Implementation is in progress. Real compiled-policy checks cover permitted filesystem work, denied outside access, exact proxy destinations, blocked direct networking, environment filtering, and audit parsing. Full Kandev lifecycle, ACP, terminal, MCP, approval ownership, UI, packaging installation, and recovery acceptance remain pending.

A session registry record has no policy digest. Normalization can return supervisor, child, and provider session identity for a matching core-owned process. It returns no confinement evidence. Core must verify birth identity and ancestry before using those identities. Audit reports remain partial because the event log does not record every denied operation.

Network grants use protocol `tcp`. Nono 0.80.0 removes ports from plain `allow_domain` entries, so the provider requires Kandev's `egress_proxy` capability for exact host/port enforcement. Core supplies a private upstream CONNECT relay. They do not enforce the application protocol. HTTP/HTTPS-specific grants and Kandev MCP relay grants remain unsupported until their integration checks pass.

## Develop

Place this checkout beside `kdlbs-kandev`, which supplies the public Go SDK:

```text
workspace/
  kdlbs-kandev/apps/backend/
  kandev-plugin-nono/
```

Run `make validate`. Run actual runtime checks with the verified executable:

```bash
NONO_ACCEPTANCE_BINARY=/absolute/path/to/nono go test ./server -run TestPinnedRuntime -count=1 -v
```

The tests verify the executable SHA-256 before starting it. They use private temporary data and no provider credentials.

## Package

`make verify-package` builds the Linux amd64 and macOS arm64 plugin executables, downloads the pinned Nono release for each, verifies the archive and executable digests, and produces `kandev-plugin-nono-0.1.0.tar.gz`. Set `NONO_RUNTIME_ARCHIVE_LINUX_AMD64` and `NONO_RUNTIME_ARCHIVE_DARWIN_ARM64` to already downloaded pinned archives for an offline package build. The plugin does not download a runtime during launch.

The package includes the Nono Apache 2.0 license and `runtime-lock.json` provenance. Plugin code uses the repository MIT license.

`.kandev-sdk-ref` must identify the committed host contract before CI or publication. Its current marker deliberately blocks CI checkout until that commit exists. There is no stable Kandev release compatibility claim yet. The manifest capability negotiation rejects hosts without this extension.

No hosted repository, marketplace entry, release, or maintainer attribution has been published from this checkout. Complete attribution and the host commit pin before an authorized publication.

### Agent session state

An explicit host `agent_state` grant gives the child a separate home. The compiler binds core-owned home, config, state, and temporary directory references to Nono `environment.set_vars`. Nono 0.80.0 applies these values after inherited-variable filtering. The supervisor keeps its private home and state directories. The plugin does not copy credentials or allocate directories. Kandev owns session retention and cleanup.

The pinned source contract is [EnvironmentConfig at the runtime commit](https://github.com/nolabs-ai/nono/blob/8bb041356d48f771a221e58c98d9b1ff442e76fe/crates/nono-cli/src/profile/mod.rs). Actual runtime verification is recorded in the host acceptance log.
