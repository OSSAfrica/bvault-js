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
 * Use release:version, release:stage, and release:finalize for the three phases.
 * `npm run release` opens the interactive changelog editor.
 * Requires Node 24+ (Tegami's floor). Note that this floor applies to
 * the release scripts only - it is deliberately not declared in `engines`,
 * because bvault-js ships to browsers and an `engines` entry would warn every
 * consumer installing on an older Node.
 */
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { format, resolveConfig } from 'prettier';
import { tegami } from 'tegami';
import { runCli } from 'tegami/cli';
import { github } from 'tegami/plugins/github';
import { normalizeCommitChangelog } from './release-changelog.mts';
import {
  assertApprovedPreview,
  PREVIEW_TAG,
  stagePreview,
  withPackedPreview,
} from './npm-staging.mts';

/** The single published package in this workspace. */
const PACKAGE_NAME = 'bvault-js';
const CHANGELOG_DIR = '.tegami';

async function writeFormattedMarkdown(filepath: string, content: string) {
  const options = await resolveConfig(filepath);
  await writeFile(filepath, await format(content, { ...options, filepath }));
}

const release = tegami({
  // Keep the 1.0 API on an opt-in channel until the stable release is ready.
  packages: {
    'bvault-js': {
      prerelease: 'preview',
      npm: { distTag: PREVIEW_TAG },
    },
  },
  // `conventionalCommits: true` is deliberately NOT set. It injects *virtual*
  // changelog entries on every draft, and because the git tag only advances at
  // publish time, the run after the version PR merges regenerates the very same
  // entries and versions a second time - 1.0.0 becomes 1.0.1 without a single
  // new commit. Materialising real files below avoids that: `draft.apply()`
  // consumes them, so they cannot be counted twice.
  plugins: [
    {
      name: 'format-release-changelog',
      // Run before GitHub's applyCliDraft hook commits the generated files.
      async applyCliDraft() {
        const filepath = join(this.cwd, 'CHANGELOG.md');
        const content = await readFile(filepath, 'utf8');
        await writeFormattedMarkdown(filepath, content);
      },
    },
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
 * Materialize conventional commits as real changelog files. This repository
 * ships one package, so both component scopes (storage, docs) and unscoped
 * commits target bvault-js. Heading depth retains Tegami's computed bump.
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
    const content = normalizeCommitChangelog(entry.content, PACKAGE_NAME);

    // Prereleases retain this source for replay into the stable changelog.
    await writeFormattedMarkdown(join(CHANGELOG_DIR, entry.filename), content);
  }

  return entries.length;
}

/**
 * Tegami's own `check-publish` exits 1 both when nothing is owed and when it
 * crashes, so CI could not tell a failed check from "nothing to publish" and
 * would carry on versioning. Print the status instead (`pending` means a
 * publish is owed); any failure then surfaces as a non-zero exit.
 */
const command = process.argv[2];
if (
  command !== undefined &&
  !['stage', 'check-publish', 'version', 'publish', '--help', '-h'].includes(
    command,
  )
) {
  throw new Error('Use release:version, release:stage, or release:finalize.');
}
if (command === 'stage') {
  await stagePreview();
} else if (command === 'check-publish') {
  const { status } = await release.getPublishStatus();
  console.log(status);
} else {
  // npm approval is the only publication gate. Tegami may only finish tags
  // and GitHub releases after these exact package bytes are publicly available.
  // Its npm task then skips the version that is already published.
  if (command === 'publish') {
    await withPackedPreview(assertApprovedPreview);
  }
  await runCli(release, {
    async version() {
      const count = await materializeCommitChangelogs();
      if (count > 0) {
        console.log(
          `[tegami] generated ${count} changelog file(s) from commits`,
        );
      }
      return release.draft();
    },
  });
}
