# Release Process

Releases are driven by [Tegami](https://tegami.fuma-nama.dev/) and, in the
normal case, by your commit messages alone.

## The short version

Write conventional commits. Merge your PR. That's it.

```
fix: stop clearing the value when decryption fails   -> patch   1.0.0 -> 1.0.1
feat: add a per-key namespace option                 -> minor   1.0.1 -> 1.1.0
feat!: drop the password-derived key path            -> major   1.1.0 -> 2.0.0
refactor: tidy the converters                        -> nothing
```

`perf:` and `revert:` also produce a patch. A `BREAKING CHANGE:` footer produces
a major, same as the `!`. Everything else — `chore:`, `docs:`, `refactor:`,
`style:`, `test:`, `ci:`, `build:` — releases nothing, which is the point: a
refactor should not publish a version.

Scopes are optional. `fix:` and `fix(bvault-js):` behave identically here.

## What happens after you merge

1. Your commit lands on `main`. The Release workflow verifies the tree (build,
   format check, tests, publint, attw).
2. No publish is owed yet, so Tegami computes the bump from the commits since
   the last tag, rewrites `package.json`, prepends to `CHANGELOG.md`, writes
   `.tegami/publish-lock.yaml`, and opens a **Version Packages** PR.
3. The App enables auto-merge on that PR. Required checks and repository rules
   still apply; maintainers can review and merge it when needed.
4. After the version PR merges, the workflow runs `npm run release:stage` in the
   `release` environment. It submits the validated preview tarball to npm using
   OIDC. Staging does not publish the version, create tags, or cut a GitHub release.
5. A maintainer opens **Staged Packages** in their npm account, reviews the
   version and `preview` tag, and approves with **2FA**. This publishes it on npm.
6. Run **Release** manually from GitHub Actions on `main`. Supply the full
   `release_commit` SHA printed in the staging summary. The workflow checks out
   that exact commit, validates it, compares its tarball with the public npm
   version, and creates the GitHub tag and prerelease. It cannot finalize an
   unpublished version or a different tarball.

The npm approval is the publication gate. The `release` environment has no
required reviewer, so staging can run automatically; its branch policy allows
only `main`. Finalization needs GitHub write access but no npm credentials or
OIDC permission. It never approves a staged package.

The current release is `1.0.0-preview.0`, under npm's `preview` dist-tag.
`latest` stays on the stable version. Install an approved preview with
`npm install bvault-js@preview`.

The publish lock is committed before staging. If staging fails before submission,
re-run the failed job. If a version is already staged, approve or reject that
existing version on npm before trying to stage it again. After npm approval,
retry finalization from the exact staged commit rather than creating a new bump.

## Setup

### The release GitHub App

Anything done with the built-in `GITHUB_TOKEN` is barred from triggering another
workflow run. So a version PR it opens gets no CI, and a merge it performs never
starts step 4 — the PR merges and then sits there.

A GitHub App token has no such restriction. The workflow mints one when these
two repository secrets exist:

| Secret                    | Where it comes from                                   |
| ------------------------- | ----------------------------------------------------- |
| `RELEASE_APP_CLIENT_ID`   | The App's settings page, "Client ID"                  |
| `RELEASE_APP_PRIVATE_KEY` | The `.pem` you download when generating a private key |

The App needs **Contents: Read and write** and **Pull requests: Read and write**
under _Repository permissions_, and must be **installed on this repository** —
creating it is not enough.

Paste the private key whole, including the `-----BEGIN RSA PRIVATE KEY-----` and
`-----END RSA PRIVATE KEY-----` lines.

Until both secrets exist the workflow falls back to `github.token`: everything
still runs, the publish just needs a nudge — re-run Release, or push any commit
to `main`.

### Branch protection

`main` is governed by the "Main Protection" ruleset, which requires one
approving review. No bot will give that, so the release App is listed in the
ruleset's **bypass actors** — otherwise auto-merge on the version PR waits
forever. Human pull requests still require review. Final publication approval
happens on npm with 2FA, after staging.

`gh pr merge --auto` also needs **Allow auto-merge** enabled in
Settings → General. Configuration errors fail the workflow; there is no
fallback to an immediate merge.

### Turning auto-merge off

Set the repository variable `AUTO_MERGE_RELEASE` to `false`. The version PR is
still opened automatically; you just review and merge it yourself.

## Publishing credentials

There are none. The workflow authenticates to npm with OIDC
([trusted publishing](https://docs.npmjs.com/trusted-publishers/)) via the
`id-token: write` permission and the `release` environment, which must match the
Trusted Publisher entry on npmjs.com:

| Field       | Value                    |
| ----------- | ------------------------ |
| Repository  | `OSSAfrica/bvault-js`    |
| Workflow    | `release.yml`            |
| Environment | `release`                |
| Permissions | `npm stage publish` only |

Do not enable direct `npm publish` for this workflow. If the publisher expires,
delete it and recreate it with the same fields and staging-only permission.
Stage before npm's validation deadline, then check its status on npm.

Provenance is generated automatically. This is also why `repository.url` in
`package.json` must point at `OSSAfrica/bvault-js` — npm validates it against
the building repository and refuses to attest a mismatch.

If you ever see the publish fall back to token auth and fail, check that the job
upgraded npm — staging requires npm >= 11.15.0 and Node >= 22.14.0. The workflow
pins npm 12.1.0 on Node 24. Check the OIDC exchange diagnostics as well: an
expired, missing, or mismatched publisher can cause the same authentication error.

## Overriding the computed version

Write a file in `.tegami/` and commit it alongside your change:

```markdown
---
packages:
  bvault-js: major
---

# Drop the password-derived key path

`initializeSecureStorage()` no longer takes a password.
```

Hand-written entries are merged with whatever the commits produced and **the
highest bump wins** — so a file can raise a release but never lower one. Use it
when the commit messages understate the impact, or when you want release notes
written in prose rather than assembled from subject lines.

`npm run release` opens Tegami's interactive prompt to write one of these for
you.

## Local commands

| Command                    | What it does                                               |
| -------------------------- | ---------------------------------------------------------- |
| `npm run release`          | Interactive changelog entry                                |
| `npm run release:version`  | Apply the bump and write the lock                          |
| `npm run release:check`    | Print `pending` while staging or GitHub work is owed       |
| `npm run release:stage`    | Stage a built preview for approval on npm                  |
| `npm run release:finalize` | Verify the approved npm tarball and finish GitHub metadata |

Build and validate with `npm run ci` before staging or finalizing locally.
Local staging needs npm authentication; CI uses OIDC instead.

Tegami requires **Node 24+**. That floor applies to these scripts only — it is
deliberately not declared in `engines`, because bvault-js ships to browsers and
an `engines` entry would warn every consumer installing on an older Node.

## Manual staging

```bash
npm run ci
npm login
npm run release:stage
```

Review and approve the staged version on npm with 2FA, then run the GitHub
finalization workflow with the commit SHA from the staging summary.
