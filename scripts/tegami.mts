/**
 * Release pipeline (Tegami).
 *
 * Versions come from conventional commits: `feat:` is a minor, `fix:`/`perf:`/
 * `revert:` a patch, and a `!` or a `BREAKING CHANGE:` footer a major. Anything
 * else (`chore:`, `docs:`, `refactor:`, `style:`, `test:`, `ci:`, `build:`)
 * releases nothing, which is what you want - a refactor should not publish.
 *
 * To override a computed bump, hand-write a file in `.tegami/`:
 *
 *     ---
 *     packages:
 *       bvault-js: major
 *     ---
 *
 *     # Why this is a major
 *
 * A hand-written file is merged with whatever the commits produced, and the
 * highest bump wins - so it can raise a version but never lower one.
 *
 * Run `npm run release` for the interactive local flow; CI runs the commands
 * directly. Requires Node 24+ (Tegami's floor). Note that this floor applies to
 * the release scripts only - it is deliberately not declared in `engines`,
 * because bvault-js ships to browsers and an `engines` entry would warn every
 * consumer installing on an older Node.
 */
import { mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tegami } from 'tegami';
import { runCli } from 'tegami/cli';
import { github } from 'tegami/plugins/github';

/** The single published package in this workspace. */
const PACKAGE_NAME = 'bvault-js';
const CHANGELOG_DIR = '.tegami';

const release = tegami({
  // `conventionalCommits: true` is deliberately NOT set. It injects *virtual*
  // changelog entries on every draft, and because the git tag only advances at
  // publish time, the run after the version PR merges regenerates the very same
  // entries and versions a second time - 1.0.0 becomes 1.0.1 without a single
  // new commit. Materialising real files below avoids that: `draft.apply()`
  // consumes them, so they cannot be counted twice.
  plugins: [
    github({
      repo: 'OSSAfrica/bvault-js',
      versionPr: { base: 'main' },
    }),
  ],
  npm: {
    // Publish through npm: trusted publishing (OIDC) is an npm CLI feature and
    // needs npm >= 11.5.1. `updateLockFile` is left at its default - this repo
    // locks with npm, so refreshing package-lock.json in the version PR is
    // exactly right.
    client: 'npm',
  },
});

/**
 * Drop git trailers from a generated changelog body.
 *
 * Entries are materialised from commit messages verbatim, so every trailer the
 * commit carried - `Signed-off-by:` from the DCO check, and any tooling that
 * stamps its own - would otherwise be published to npm inside CHANGELOG.md.
 * Trailers are metadata about the commit, not release notes.
 *
 * `Refs`/`Closes`/`Fixes` are deliberately kept: they point at issues a reader
 * of the changelog may genuinely want.
 */
const DROPPED_TRAILER =
  /^(?:signed-off-by|co-authored-by|claude-session|reviewed-by|reported-by|tested-by|acked-by|cc):[ \t].*$/gim;

function stripTrailers(content: string): string {
  return content.replace(DROPPED_TRAILER, '').replace(/\n{3,}(?=\n*$)/, '\n');
}

/**
 * Turn conventional commits since the last tag into real changelog files.
 *
 * Tegami resolves a commit's affected packages from its scope, so an *unscoped*
 * `fix: ...` resolves to no package and releases nothing - and this repo's
 * history is unscoped throughout. In a single-package workspace the target is
 * never ambiguous, so an entry that names no package is pointed at this one.
 *
 * The rewrite uses the implicit style (`packages: ["bvault-js"]`), which lets
 * Tegami keep deriving the bump from heading depth in the generated body rather
 * than us recomputing it.
 */
async function materializeCommitChangelogs(): Promise<number> {
  // Never write while a publish is still owed: the lock is mid-flight, the tag
  // has not moved yet, and these same commits would regenerate into an orphan
  // file that the blocked version run leaves behind.
  const { status } = await release.getPublishStatus();
  if (status === 'pending') return 0;

  const entries = await release.generateChangelog({ write: false });
  if (entries.length === 0) return 0;

  await mkdir(CHANGELOG_DIR, { recursive: true });

  for (const entry of entries) {
    const unscoped = Object.keys(entry.packages).length === 0;
    const stripped = stripTrailers(entry.content);
    const content = unscoped
      ? stripped.replace(
          /^---\npackages: \{\}\n---\n/,
          `---\npackages: ["${PACKAGE_NAME}"]\n---\n`,
        )
      : stripped;

    await writeFile(join(CHANGELOG_DIR, entry.filename), content);
  }

  return entries.length;
}

await runCli(release, {
  async version() {
    const count = await materializeCommitChangelogs();
    if (count > 0) {
      console.log(`[tegami] generated ${count} changelog file(s) from commits`);
    }
    return release.draft();
  },
});
