import { execFile } from 'node:child_process';
import { appendFile, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { promisify } from 'node:util';

const exec = promisify(execFile);
export const PREVIEW_TAG = 'preview';

export interface PackedRelease {
  name: string;
  version: string;
  integrity: string;
  filename: string;
}

/** Pack once, then submit those exact bytes to npm's staging area. */
export async function withPackedPreview<T>(
  action: (release: PackedRelease) => Promise<T>,
): Promise<T> {
  const manifest = JSON.parse(await readFile('package.json', 'utf8'));
  if (
    manifest.name !== 'bvault-js' ||
    !/^\d+\.\d+\.\d+-preview\.\d+$/.test(manifest.version)
  ) {
    throw new Error('Expected a bvault-js preview version before staging.');
  }

  const directory = await mkdtemp(join(tmpdir(), 'bvault-release-'));
  try {
    // CI has already built and validated the package. Avoid lifecycle output
    // in the JSON response and keep the tarball out of the working tree.
    const { stdout } = await exec('npm', [
      'pack',
      '--ignore-scripts',
      '--json',
      '--pack-destination',
      directory,
    ]);
    const output = JSON.parse(stdout);
    const [packed] = Array.isArray(output) ? output : Object.values(output);
    if (
      packed?.name !== manifest.name ||
      packed?.version !== manifest.version ||
      !packed?.integrity?.startsWith('sha512-') ||
      !packed?.filename
    ) {
      throw new Error('npm pack did not return the expected preview package.');
    }
    return await action({
      ...packed,
      filename: join(directory, packed.filename),
    });
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

/** A public, byte-for-byte matching version proves npm approval has finished. */
export async function assertApprovedPreview(
  release: PackedRelease,
  fetchRegistry: typeof fetch = fetch,
): Promise<void> {
  const response = await fetchRegistry(
    `https://registry.npmjs.org/${encodeURIComponent(release.name)}`,
    {
      headers: { 'Cache-Control': 'no-cache' },
      signal: AbortSignal.timeout(30_000),
    },
  );
  if (!response.ok) {
    throw new Error(
      `Cannot verify npm approval: registry HTTP ${response.status}.`,
    );
  }
  const metadata = await response.json();
  const published = metadata.versions?.[release.version];
  if (!published) {
    throw new Error(
      `Approve ${release.name}@${release.version} on npm with 2FA before finalizing.`,
    );
  }
  if (published.dist?.integrity !== release.integrity) {
    throw new Error(
      'The approved npm tarball does not match this release commit.',
    );
  }
  if (
    metadata['dist-tags']?.[PREVIEW_TAG] !== release.version ||
    metadata['dist-tags']?.latest === release.version
  ) {
    throw new Error(
      'Expected the approved preview on preview, without moving latest.',
    );
  }
}

export async function stagePreview(): Promise<void> {
  await withPackedPreview(async (release) => {
    const { stdout, stderr } = await exec(
      'npm',
      ['stage', 'publish', release.filename, '--tag', PREVIEW_TAG, '--json'],
      { maxBuffer: 4 * 1024 * 1024 },
    );
    process.stdout.write(stdout);
    process.stderr.write(stderr);
    const { stdout: commit } = await exec('git', ['rev-parse', 'HEAD']);
    const summary = [
      `## Awaiting npm approval: ${release.name}@${release.version}`,
      '',
      `Staged with the **${PREVIEW_TAG}** tag. This version is not public yet.`,
      'Review it in your npm account’s Staged Packages tab and approve with 2FA.',
      '',
      'After approval, run the **Release** workflow manually on main with',
      `**release_commit** set to \`${commit.trim()}\`.`,
      'That run checks the approved tarball before creating GitHub tags and a prerelease.',
      '',
      `Tarball integrity: \`${release.integrity}\``,
      '',
    ].join('\n');
    console.log(summary);
    if (process.env.GITHUB_STEP_SUMMARY) {
      await appendFile(process.env.GITHUB_STEP_SUMMARY, summary);
    }
  });
}
