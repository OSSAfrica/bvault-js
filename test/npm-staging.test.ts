// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { assertApprovedPreview } from '../scripts/npm-staging.mts';

const release = {
  name: 'bvault-js',
  version: '1.0.0-preview.0',
  integrity: 'sha512-approved-package',
  filename: '/tmp/unused-preview.tgz',
};

function registry(
  versions: Record<string, unknown>,
  tags = { preview: release.version, latest: '0.3.4' },
) {
  return vi
    .fn<typeof fetch>()
    .mockResolvedValue(Response.json({ versions, 'dist-tags': tags }));
}

const approved = {
  [release.version]: { dist: { integrity: release.integrity } },
};

describe('npm staging approval gate', () => {
  it('blocks finalization while the staged version is not public', async () => {
    await expect(assertApprovedPreview(release, registry({}))).rejects.toThrow(
      'Approve bvault-js@1.0.0-preview.0 on npm with 2FA',
    );
  });

  it('blocks an approved package built from different release bytes', async () => {
    await expect(
      assertApprovedPreview(
        release,
        registry({
          [release.version]: { dist: { integrity: 'sha512-other' } },
        }),
      ),
    ).rejects.toThrow('does not match this release commit');
  });

  it('blocks a version whose preview tag is missing or points elsewhere', async () => {
    await expect(
      assertApprovedPreview(
        release,
        registry(approved, { preview: '1.0.0-preview.1', latest: '0.3.4' }),
      ),
    ).rejects.toThrow('without moving latest');
  });

  it('blocks a preview accidentally promoted to latest', async () => {
    await expect(
      assertApprovedPreview(
        release,
        registry(approved, {
          preview: release.version,
          latest: release.version,
        }),
      ),
    ).rejects.toThrow('without moving latest');
  });

  it('fails closed when npm is unavailable', async () => {
    const fetchRegistry = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 503 }));
    await expect(assertApprovedPreview(release, fetchRegistry)).rejects.toThrow(
      'registry HTTP 503',
    );
  });

  it('allows only a matching public preview and leaves stable latest intact', async () => {
    await expect(
      assertApprovedPreview(release, registry(approved)),
    ).resolves.toBeUndefined();
  });
});
