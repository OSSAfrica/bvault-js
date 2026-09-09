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
3. That PR is auto-merged.
4. The merge lands on `main`, the workflow runs again and sees a publish is
   owed. The publish job targets the `release` environment, which has a required
   reviewer — so it pauses for approval, then ships to npm with provenance, tags
   the commit and cuts a GitHub release.

Only step 4 asks for a human. Publishing is the single irreversible action in
the chain; versioning and opening a PR are both revertable, which is why they
sit in a separate job outside the environment. Approve from the run page, or
from the Actions tab — GitHub also emails the reviewer.

The publish lock is committed before anything is published, so a failed publish
can be retried by re-running the job rather than re-versioning.

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
forever. Human pull requests still require review; the release gate lives on the
`release` environment instead, before anything reaches npm.

`gh pr merge --auto` also needs **Allow auto-merge** enabled in
Settings → General; the workflow falls back to an immediate merge if it isn't.

### Turning auto-merge off

Set the repository variable `AUTO_MERGE_RELEASE` to `false`. The version PR is
still opened automatically; you just review and merge it yourself.

## Publishing credentials

There are none. The workflow authenticates to npm with OIDC
([trusted publishing](https://docs.npmjs.com/trusted-publishers/)) via the
`id-token: write` permission and the `release` environment, which must match the
Trusted Publisher entry on npmjs.com:

| Field       | Value                 |
| ----------- | --------------------- |
| Repository  | `OSSAfrica/bvault-js` |
| Workflow    | `release.yml`         |
| Environment | `release`             |

Provenance is generated automatically. This is also why `repository.url` in
`package.json` must point at `OSSAfrica/bvault-js` — npm validates it against
the building repository and refuses to attest a mismatch.

If you ever see the publish fall back to token auth and fail, check that the job
upgraded npm — trusted publishing needs npm >= 11.5.1, and the npm bundled with
Node is older.

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

| Command                   | What it does                      |
| ------------------------- | --------------------------------- |
| `npm run release`         | Interactive changelog entry       |
| `npm run release:version` | Apply the bump and write the lock |
| `npm run release:check`   | Exit 0 if a publish is owed       |
| `npm run release:publish` | Publish from the lock             |

Tegami requires **Node 24+**. That floor applies to these scripts only — it is
deliberately not declared in `engines`, because bvault-js ships to browsers and
an `engines` entry would warn every consumer installing on an older Node.

## Emergency manual release

```bash
npm run ci
npm login
npm publish
```
