# ADR 0001: Pin every action to a commit SHA and let Dependabot move the pins

- **Status:** Accepted
- **Date:** 2026-11-20

## Context

A workflow step such as `uses: some-org/action@v2` runs whatever code that tag points to at run time,
with the job's token and secrets. Tags and branches can be moved by the action's maintainer or by an
attacker who compromises their account; this has happened in real incidents, where a popular
action's tags were repointed to code that dumped CI secrets into build logs.

## Options

| Option | Security | Maintenance |
|---|---|---|
| A. Branch (`@main`) | Worst: any push changes what runs | None, until it breaks |
| B. Release tag (`@v4`) | Mutable; trusts the maintainer's account | Low |
| C. Full commit SHA + version comment | Immutable: the reviewed code is the code that runs | Needs automated updates |
| D. Vendor actions into the repo | Immutable and auditable | High: manual updates |

## Decision

Option C for every action, first-party included. Dependabot (`package-ecosystem: github-actions`)
opens grouped pull requests that update the SHA and its version comment together, so pins stay
current and every change is reviewed and tested before it lands.

`pipeguard` enforces the policy: a branch reference is an **error** (PG004), a tag is a
**warning** (PG003). This repository runs with `--fail-on warning`, so it cannot merge a tag pin.

## Consequences

- Upgrading an action is a reviewed pull request, not a silent change.
- SHAs are not human-readable; the trailing `# vX.Y.Z` comment is required for reviewers.
- A SHA pin does not protect against an action that itself downloads unpinned code at run time;
  that risk is reduced by preferring first-party and well-maintained actions.

## Revisit when

- GitHub offers immutable releases or signed provenance for actions that the runner verifies.
