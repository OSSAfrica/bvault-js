# Contributing to bVault-js

Contributions go through pull requests targeting `main`. Sign off and
cryptographically sign every contribution commit, run the checks relevant to your
change, and explain the resulting behavior and validation.

Follow the [OSSAfrica contribution guide](https://github.com/OSSAfrica/.github/blob/main/CONTRIBUTING.md)
and [Code of Conduct](https://github.com/OSSAfrica/.github/blob/main/CODE_OF_CONDUCT.md).
The notes below cover bVault-specific development and commit requirements.

## Discuss the change

- Search [existing issues](https://github.com/OSSAfrica/bvault-js/issues) before
  reporting a bug. Include the library version, browser or runtime, reproduction
  steps, expected behavior and actual behavior. Use synthetic data in examples.
- Open an issue before a substantial feature, API or cryptographic change so
  maintainers can discuss scope and compatibility.
- For vulnerabilities, use
  [GitHub's private reporting option](https://github.com/OSSAfrica/bvault-js/security)
  when available. Otherwise, ask a maintainer for a private reporting channel
  before sharing exploit details. Keep credentials, private keys and user data out
  of public issues and pull requests.

## Set up a branch

Fork the repository, then replace `YOUR_USERNAME` and the example branch name:

```sh
git clone https://github.com/YOUR_USERNAME/bvault-js.git
cd bvault-js
git remote add upstream https://github.com/OSSAfrica/bvault-js.git
git fetch upstream
git switch -c fix/describe-your-change upstream/main
```

Use Node.js **24 or newer** and npm, matching the Tegami release tooling and the
release workflow on `main`.

```sh
npm install
npm test
```

`npm install` runs the package's `prepare` script to compile TypeScript. `npm test`
starts Vitest in watch mode; use `npm run test:run` for a single run.

## Current design

Development targets the 1.0 browser-storage API described in
[issue #5](https://github.com/OSSAfrica/bvault-js/issues/5). Encryption uses the
browser's asynchronous Web Crypto API with a generated, non-extractable AES-GCM
`CryptoKey` persisted in IndexedDB. `initializeSecureStorage()` takes no password.
The public API focuses on secure storage wrappers and key lifecycle operations.

Preserve the non-extractable-key boundary: do not export raw key bytes or
reintroduce password or fingerprint derivation. Keep threat-model claims precise:
storage-copy protection does not prevent live script in the origin from using the
key, or protect against an attacker reading the whole browser profile.

Read [How bVault-js works](docs/how-bvault-works.md) for the architecture,
key lifecycle, payload format and known limitations.

## Commit requirements

### DCO sign-off and cryptographic signing

Every contribution commit, including follow-up fixes, needs both:

| Requirement                                    | Git option                    | What it does                                                       |
| ---------------------------------------------- | ----------------------------- | ------------------------------------------------------------------ |
| Developer Certificate of Origin (DCO) sign-off | Lowercase `-s` / `--signoff`  | Adds a `Signed-off-by: Name <email>` trailer to the commit message |
| Cryptographic signature                        | Uppercase `-S` / `--gpg-sign` | Signs the commit with your configured signing key                  |

Use both when committing:

```sh
git add path/to/changed-file
git commit -S -s -m "fix(storage): describe the behavior being corrected"
```

A DCO trailer does not sign the commit cryptographically, and a cryptographic
signature does not add a DCO trailer. Signing only the latest commit leaves earlier
commits unchanged.

### DCO compliance

See the [repository DCO guidance](https://github.com/OSSAfrica/bvault-js/blob/main/DCO.md).
Read the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
before signing off. The sign-off certifies your right to submit the contribution
under the applicable open source license. bVault-js uses the [MIT license](LICENSE).
Your sign-off becomes part of the public commit history.

Configure your own identity for this checkout:

```sh
git config --local user.name "Your Name"
git config --local user.email "you@example.com"
```

For your own commits, the sign-off must match the commit author's name and email.
Use an email associated with your GitHub account; a correctly configured GitHub
noreply address can preserve email privacy. Preserve other contributors' authorship
and sign-offs. Do not add a sign-off on someone else's behalf.

The DCO GitHub App checks sign-off compliance on pull requests. A trailer in the
PR description or a later commit does not repair a missing trailer in an earlier
commit.

### GPG signing setup

The active `main` ruleset requires verified signatures. This guide uses GPG;
GitHub also supports SSH and S/MIME signing. If you already use one of those
methods with GitHub-verified signatures, keep its matching configuration.

1. Install GPG and check for an existing signing key:

   ```sh
   gpg --list-secret-keys --keyid-format=long
   ```

2. If you need a key, generate one with an email associated with your GitHub
   account and protect it with a passphrase:

   ```sh
   gpg --full-generate-key
   ```

   See [GitHub's GPG key guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key).

3. Replace `YOUR_GPG_KEY_ID` with your signing key ID and export its public key:

   ```sh
   gpg --armor --export YOUR_GPG_KEY_ID
   ```

   Add that **public** key to GitHub under **Settings → SSH and GPG keys → New
   GPG key**. Keep the private key private. The committer email must match an email
   on the key and be verified on GitHub (or be your GitHub-provided noreply address).
   See [adding a GPG key to GitHub](https://docs.github.com/en/authentication/managing-commit-signature-verification/adding-a-gpg-key-to-your-github-account).

4. Configure this checkout:

   ```sh
   git config --local gpg.format openpgp
   git config --local user.signingkey YOUR_GPG_KEY_ID
   git config --local commit.gpgsign true
   ```

Signing by default does not add DCO sign-off. Continue using `git commit -S -s`.
See [GitHub's signing guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)
for platform-specific configuration.

Before pushing, inspect all contribution commits:

```sh
git log --show-signature upstream/main..HEAD
git log --format='%h %an <%ae>%n%B' upstream/main..HEAD
```

After pushing, check each commit's **Verified** status in the PR's **Commits** tab
and inspect the DCO check results. A locally valid signature alone does not prove
that GitHub recognizes the key and email.

### Repairing your commits

For your own latest unpushed commit, add the sign-off and signature with:

```sh
git commit --amend --no-edit -S -s
```

For earlier or already-pushed commits, coordinate before rewriting a shared branch.
One option that preserves the existing branch is to create a replacement branch
and copy your own ordinary commits, oldest first:

```sh
git fetch upstream
git switch -c fix/signed-contribution upstream/main
git cherry-pick -S -s YOUR_COMMIT_SHA
git push -u origin HEAD
```

Repeat for the relevant commits, retest and link the replacement PR to the original.
For mixed authors or merge commits, ask a maintainer for help preserving attribution.
If you rebase, recreated commits also need valid sign-offs and fresh signatures.

## Local validation and coding standards

Run the project's combined checks before pushing:

```sh
npm run ci
git diff --check
```

`npm run ci` compiles TypeScript, checks Prettier formatting and runs Vitest once.
You can also run the checks individually:

```sh
npm run build
npm run check-format
npm run test:run
```

- Follow the existing TypeScript style and use Prettier for files you change.
- Add focused regression tests for behavior changes. Cryptographic changes should
  cover round trips, tampered ciphertext, key persistence, key loss and refusal to
  export the key. Storage changes should preserve SSR-safe imports and keep
  undecryptable entries intact. Explain when real-browser validation is needed
  beyond jsdom and fake-indexeddb.
- Explain changes to encryption parameters, stored formats or public APIs, including
  compatibility and migration implications. Update affected documentation and examples.
- Keep dependency changes justified and include relevant lockfile changes. Keep
  secrets, generated builds and unrelated edits out of commits.
- Documentation-only changes need formatting, working links and accurate examples.
- Use Conventional Commit subjects such as `feat(storage): ...`,
  `fix(storage): ...` or `docs: ...`; release tooling uses them to determine version
  bumps. Keep unrelated changes in separate commits or PRs.

## Submit and review the pull request

Push your branch and open a PR against `OSSAfrica/bvault-js:main`:

```sh
git push -u origin HEAD
```

Explain the problem, resulting behavior, checks performed and any limitations.
Link the relevant issue and describe breaking changes. Mark unfinished work as a
draft. Address reviewer feedback and resolve applicable CI and security findings.

To bring your branch up to date while preserving existing commits:

```sh
git fetch upstream
git merge -S --signoff upstream/main
git push origin HEAD
```

Resolve conflicts and rerun the relevant checks before pushing.

As checked on **10 November 2026**, the
[active ruleset](https://github.com/OSSAfrica/bvault-js/rules/20919557) requires a
pull request, at least one qualifying approval, verified signatures, CodeQL results
meeting its thresholds and Code Quality results meeting its error threshold. It
also requires an additional approval for unattributed changes and blocks force
pushes and deletion of `main`. The PR merge box shows the current enforced gates.
DCO sign-off is contribution policy and is checked by the DCO GitHub App; it is
separate from signature verification.

Before requesting merge:

- [ ] Every contribution commit has a matching DCO trailer and a GitHub-verified signature.
- [ ] Relevant checks pass, with skipped tests and limitations explained.
- [ ] Tests, documentation and examples reflect the resulting behavior.
- [ ] Review feedback and applicable security findings are addressed.
- [ ] The PR meets the current approval and merge requirements.

Fork workflows may need maintainer approval to run. That permission is separate
from approval to merge. Inspect failing check details and share sanitized logs when
asking for help.

## Versioning

The `main` branch uses Tegami and the
[release workflow](https://github.com/OSSAfrica/bvault-js/blob/main/.github/workflows/release.yml)
for versioning and publishing. Use Conventional Commits: `fix:` for a patch,
`feat:` for a minor release, and `!` or a `BREAKING CHANGE:` footer for a breaking
change. Explain the migration impact in the commit body and pull request.

Contributors do not need to add a changeset or manually bump the package version.
Leave version pull requests, publishing and release tags to the release workflow
and maintainers. npm publishing uses GitHub OIDC trusted publishing.
