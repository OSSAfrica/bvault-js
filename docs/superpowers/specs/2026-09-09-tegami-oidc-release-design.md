# Tegami + OIDC release pipeline for bvault-js

**Date:** 2026-09-09
**Status:** Approved for planning
**Scope:** Replace changesets with Tegami and publish to npm without registry tokens.

## Problem

bvault-js has no working release automation. `.github/workflows/release.yml` is a
0-byte file: commit `f56dc6b` ("ci: remove GitHub Actions release workflow",
2025-08-04) deleted all 52 lines of content but left the file in the tree.
GitHub parses every `*.yml` under `.github/workflows/`, finds no `on:` key, and
fails with `No event triggers defined in 'on'` on **every push to main**. This
has been failing since August 2025; the PR #6 merge commit `fb1f2c9` was simply
the next push.

Releases are therefore manual, authenticated with a long-lived `NPM_TOKEN`
repository secret. The registry has drifted ahead of the repository as a result:
npm `latest` is **0.3.4** while `package.json` says **0.3.2**.

A major release is already owed. `.changeset/non-extractable-keys.md` declares a
`major` bump for the non-extractable-CryptoKey work merged in PR #6.

## Goals

1. Publish to npm with **no registry token**, using npm Trusted Publishing
   (OIDC) with provenance.
2. Drive versions from conventional commits via Tegami, matching the sibling
   repo `VedaTrace/vedatrace-npm`.
3. Keep exactly one human gate, on the single irreversible step: the publish.
4. Fix the empty-workflow failure as part of the change.

## Non-goals

- Migrating bvault-js to Bun. The repo stays npm-locked.
- Rewriting existing non-conventional commit history.
- Changing the library's public API or build output.

## Decisions

| Question | Decision |
|---|---|
| Release tooling | Migrate changesets → Tegami |
| Toolchain | Keep npm (`npm ci`, `npm run`); Node 24+ |
| Automation level | Full loop: GitHub App opens and auto-merges the version PR; publish gated on a `release` environment with a required reviewer |
| `main` ruleset conflict | Add the release GitHub App to the ruleset's `bypass_actors` |

### Why a GitHub App at all

The App does **not** publish to npm. Anything performed with the built-in
`GITHUB_TOKEN` is barred from triggering another workflow run, so a version PR
it opens receives no CI and a merge it performs never starts the publish job.
An App token has no such restriction, which is what closes the loop. npm
authentication is entirely separate and uses OIDC.

## Blockers found, and their resolutions

### B1 — Provenance will reject the publish

`package.json` points at the wrong repository:

```
repository.url  git+https://github.com/kurtiz/bvault-js.git
bugs.url        https://github.com/kurtiz/bvault-js/issues
homepage        https://github.com/kurtiz/bvault-js#readme
```

The repository is `OSSAfrica/bvault-js`. npm validates `repository.url` against
the building repository when generating provenance. **Resolution:** rewrite all
three fields to `OSSAfrica/bvault-js`.

### B2 — No git tags exist

`git tag -l` returns nothing, locally and on the remote. Tegami reads commits
back to the latest tag; with no floor, the first `release:version` run would
materialise changelog entries from the entire history.

**Resolution:** create and push tag `v0.3.4` at commit `1886cb1` — main's tip
immediately before the PR #6 work began. Tegami's first run then sees only PR
#6's commits.

### B3 — Registry/repository version drift

npm `latest` is 0.3.4; `package.json` is 0.3.2. **Resolution:** set
`package.json` to `0.3.4` in the same change as B2, so the tag, the manifest and
the registry agree before Tegami runs. The computed bump is `major` either way,
so this does not change the resulting version — it prevents a confusing
changelog and a tag that disagrees with the manifest.

### B4 — `main` ruleset blocks the version PR

Ruleset "Main Protection" (id `20919557`) applies to the default branch with
`bypass_actors: []` and:

- `pull_request` → `required_approving_review_count: 1`,
  `require_extra_approval_for_unattributed_changes: true`
- `required_signatures`
- `deletion`, `non_fast_forward`, `code_scanning`, `code_quality`

`required_signatures` is satisfied: GitHub signs the squash-merge commits it
creates. The approval requirement is the wall — `gh pr merge --auto` would wait
for an approval no bot will give.

**Resolution:** add the release App to `bypass_actors`. Human PRs keep requiring
review; the release gate moves to the `release` environment, before npm.

## Design

### Version floor and manifest reconciliation

```
git tag v0.3.4 1886cb1 && git push origin v0.3.4
package.json: version 0.3.2 -> 0.3.4
```

### `package.json`

- Remove `@changesets/cli` from `devDependencies`.
- Remove the `local-release` script (`changeset version && changeset publish`).
- Add `tegami@^1.5.0` to `devDependencies`.
- Add release scripts:

```json
"release":         "node scripts/tegami.mts",
"release:version": "node scripts/tegami.mts version",
"release:publish": "node scripts/tegami.mts publish",
"release:check":   "node scripts/tegami.mts check-publish"
```

- Rewrite `repository.url`, `bugs.url`, `homepage` per B1.
- Do **not** add `engines.node`. Tegami's Node 24 floor binds the release
  scripts, not the published package; bvault-js is a browser library, and an
  `engines` entry would emit `EBADENGINE` warnings for every consumer
  installing on Node 20 or 22. The floor is documented in `RELEASE.md` and
  enforced by the workflow pinning `node-version: 24`.

### `scripts/tegami.mts` (new)

Ported from `vedatrace-npm/scripts/tegami.mts`, run by plain `node` (Node 24
strips types natively). Three deliberate differences:

| Element | vedatrace | bvault-js | Reason |
|---|---|---|---|
| `PACKAGE_NAME` | `vedatrace` | `bvault-js` | |
| `github({repo})` | `VedaTrace/vedatrace-npm` | `OSSAfrica/bvault-js` | |
| `npm.updateLockFile` | `false` | default (`true`) | vedatrace disables it to stop a stray `package-lock.json` landing beside `bun.lock`. bvault-js *is* npm-locked, so refreshing the lockfile in the version PR is correct. |

`npm.client` stays `"npm"` — trusted publishing is an npm CLI feature.

The `syncSdkVersion` plugin is **dropped**: nothing in bvault-js `src/` stamps a
version string, unlike vedatrace's `src/version.ts`.

`materializeCommitChangelogs()` is kept verbatim in intent. It matters here for
the same reason: Tegami resolves a commit's affected packages from its scope, and
bvault-js's history is unscoped throughout (`feat!:`, not `feat(bvault-js)!:`),
so an unscoped commit would otherwise resolve to no package and release nothing.
`conventionalCommits: true` stays off for the reason documented in the vedatrace
script — it injects virtual entries that regenerate and double-version.

### `.tegami/1.0.0-non-extractable-keys.md` (new)

The body of `.changeset/non-extractable-keys.md` is carried over unchanged —
hand-written prose notes are better release notes than assembled subject lines,
and they already declare `major`. Frontmatter becomes:

```yaml
---
packages:
  bvault-js: major
---
```

`.changeset/` (`config.json`, `README.md`, `non-extractable-keys.md`) is deleted.

### `.github/workflows/release.yml`

Replaces the 0-byte file, resolving the `No event triggers defined in 'on'`
failure. Two jobs, mirroring vedatrace:

```yaml
on:
  push:
    branches: [main]

concurrency: ${{ github.workflow }}-${{ github.ref }}
```

**Job `version`** — `permissions: contents: write, pull-requests: write`

1. `actions/checkout@v7` with `fetch-depth: 0` (Tegami needs history back to the tag).
2. Mint the App token via `actions/create-github-app-token@v3`, guarded by a
   job-level `env: RELEASE_APP_CLIENT_ID` — the `secrets` context is not readable
   from a step-level `if`, and referencing it there is a workflow syntax error
   that fails the whole file at startup, including the branch filters.
3. `actions/setup-node@v7` with `node-version: '24'`.
4. `npm ci`.
5. Verify: `npm run build`, `npm run check-format`, `npm run test:run`,
   `npx publint@latest`, `npx @arethetypeswrong/cli@latest --pack . --profile node16`.
6. `npm run release:check` → output `publish=true|false`.
7. If `publish == false`: `npm run release:version`, then enable auto-merge on
   the `tegami/version-packages` PR unless repo variable `AUTO_MERGE_RELEASE` is
   `false`.

**Job `publish`** — `needs: version`, `if: needs.version.outputs.publish == 'true'`

- `environment: release` (name must match the npm Trusted Publisher entry).
- `permissions: contents: write, id-token: write`. No `NPM_TOKEN`.
- Node 24, then **`npm install -g npm@latest`** — trusted publishing needs
  npm >= 11.5.1 and the npm bundled with Node is older; without this the publish
  silently falls back to token auth and fails.
- No `registry-url` on `setup-node`: an `.npmrc` carrying a token would make npm
  authenticate with that token instead of performing the OIDC exchange.
- `npm ci`, `npm run build`, `npm run release:publish`.

### `RELEASE.md` (new)

Adapted from vedatrace's, describing the commit-message contract, the two-state
workflow, the `.tegami/` override, the `AUTO_MERGE_RELEASE` escape hatch, and
the "there are no publishing credentials" section.

## Out-of-band setup

Steps 1–3 cannot be performed from this repo and are the user's to do.

1. **GitHub App** — Repository permissions *Contents: Read and write* and
   *Pull requests: Read and write*. Install it on `OSSAfrica/bvault-js`;
   creating it is not sufficient. Add secrets `RELEASE_APP_CLIENT_ID` (App
   settings → Client ID) and `RELEASE_APP_PRIVATE_KEY` (the generated `.pem`,
   pasted whole including the BEGIN/END lines).
2. **`release` environment** — create it with the user as a required reviewer.
3. **npm Trusted Publisher** — on npmjs.com, package `bvault-js` → Settings →
   Trusted Publisher: repository `OSSAfrica/bvault-js`, workflow `release.yml`,
   environment `release`. Tied to the `papilio` maintainer account.
4. **Ruleset bypass** — add the App to ruleset `20919557` `bypass_actors`
   (can be done via API once the App exists).
5. **Retire tokens** — delete the `NPM_TOKEN` and `P_TOKEN` repository secrets
   after the first successful publish.

Until the App secrets exist the workflow falls back to `github.token`:
everything still runs, the publish just needs a nudge (re-run Release, or push
any commit to main).

## Verification

- `npm run release:check` exits non-zero on a clean tree with no owed publish.
- Dry run: on a scratch branch, confirm `npm run release:version` computes
  0.3.4 → 1.0.0 from the ported `.tegami` entry and rewrites `package.json`,
  `CHANGELOG.md` and `.tegami/publish-lock.yaml`.
- `npx publint` and `attw` pass against the built tarball.
- First real run is observed end to end: version PR opens with CI, auto-merges,
  publish job pauses for approval, then ships 1.0.0 with provenance.
- Confirm on npm that 1.0.0 shows a provenance attestation naming
  `OSSAfrica/bvault-js`.

## Risks and open questions

- **`require_extra_approval_for_unattributed_changes: true`** — it is not
  established whether a `bypass_actors` entry clears this as well as the
  approval count. If the version PR stalls despite the bypass, fall back to
  repository variable `AUTO_MERGE_RELEASE=false` and merge it by hand. To be
  settled by observing the first run rather than guessed at now.
- **Conventional commits become load-bearing.** Existing history is mixed —
  `Increase PBKDF2 iterations from 100k to 600k` and `Potential fix for code
  scanning alert no. 1` would release nothing. Going-forward concern only;
  `.tegami/` entries override when commit messages understate impact.
- **Tag placement.** `v0.3.4` at `1886cb1` asserts that everything before that
  commit shipped as 0.3.4. Since 0.3.4 was published by hand and never recorded
  in the repo, this is a reconstruction, not a record.
- **Node 24 floor** may exclude contributors on older runtimes from running the
  release scripts. Build and test are unaffected.

## Rollback

Every step is revertable before the publish job runs. After a publish, npm
versions are immutable — 1.0.0 could only be deprecated and superseded, not
withdrawn. Restoring changesets means reverting the commit and reinstating
`@changesets/cli`; the deleted `.changeset/` entry survives in git history.
