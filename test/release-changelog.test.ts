import { describe, expect, it } from 'vitest';
import { normalizeCommitChangelog } from '../scripts/release-changelog.mts';

describe('single-package conventional commits', () => {
  it.each([
    ['packages: {}', '### A patch'],
    ['packages:\n  storage:\n    type: patch', '### A scoped patch'],
    ['packages:\n  docs:\n    type: minor', '## A scoped feature'],
    ['packages:\n  bvault-js:\n    type: major', '# A breaking change'],
  ])(
    'targets bvault-js for %s without changing its bump heading',
    (packages, heading) => {
      const result = normalizeCommitChangelog(
        `---\n${packages}\n---\n\n${heading}\n\nCloses #9\nSigned-off-by: Contributor <dev@example.com>\n`,
        'bvault-js',
      );
      expect(result).toContain('---\npackages: ["bvault-js"]\n---\n');
      expect(result).toContain(`\n${heading}\n`);
      expect(result).toContain('Closes #9');
      expect(result).not.toContain('Signed-off-by:');
    },
  );

  it('preserves migration notes while removing commit trailers', () => {
    const result = normalizeCommitChangelog(
      '---\npackages: {}\n---\n\n# New API\n\nBREAKING CHANGE: replace the old API.\nRefs #5\nReviewed-by: Reviewer <review@example.com>\n',
      'bvault-js',
    );
    expect(result).toContain('BREAKING CHANGE: replace the old API.');
    expect(result).toContain('Refs #5');
    expect(result).not.toContain('Reviewed-by:');
  });

  it('fails clearly for an unexpected generated format', () => {
    expect(() =>
      normalizeCommitChangelog('### no frontmatter', 'bvault-js'),
    ).toThrow('no frontmatter');
  });
});
