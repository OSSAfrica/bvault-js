const DROPPED_TRAILER =
  /^(?:signed-off-by|co-authored-by|claude-session|reviewed-by|reported-by|tested-by|acked-by|cc):[ \t].*$/gim;

/** Scopes describe components in this single-package repo, not npm packages. */
export function normalizeCommitChangelog(
  content: string,
  packageName: string,
): string {
  const stripped = content
    .replace(DROPPED_TRAILER, '')
    .replace(/\n{3,}(?=\n*$)/, '\n');
  const header = /^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/;
  if (!header.test(stripped))
    throw new Error('Generated changelog has no frontmatter.');
  // Keep the headings and body: their depth still determines the bump.
  // Only newly generated commit entries pass through here, never replay files.
  return stripped.replace(
    header,
    `---\npackages: [${JSON.stringify(packageName)}]\n---\n`,
  );
}
