# Developer Certificate of Origin (DCO)

All contributions to this repository must be signed off in commit messages.

## Why this is required

OSSAfrica uses the Developer Certificate of Origin (DCO) to confirm that
contributors have the right to submit their changes.

DCO reference: [developercertificate.org](https://developercertificate.org/)

## How to sign off commits

Use `-s` when committing:

```bash
git commit -s -m "your commit message"
```

This adds a line like:

```text
Signed-off-by: Your Name <you@example.com>
```

## Fix an unsigned commit

For the latest commit:

```bash
git commit --amend -s --no-edit
```

For multiple local commits (rebase and amend each commit):

```bash
git rebase -i HEAD~N
```

Then amend each selected commit with sign-off.
