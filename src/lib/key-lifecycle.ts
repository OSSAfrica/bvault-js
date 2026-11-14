/** Coordination metadata only; no key material is ever broadcast or serialized. */
const MARKER = 'bvault:key-lifecycle';
const CHANNEL = 'bvault:key-lifecycle';
let revision: string | null | undefined;
let channel: BroadcastChannel | undefined;
let invalidate: (() => void) | undefined;

function readRevision(): string | null {
  try {
    return globalThis.localStorage?.getItem(MARKER) ?? null;
  } catch {
    // Session-only use can still work when localStorage access is restricted.
    return null;
  }
}

function observeRevision(): string | null {
  const current = readRevision();
  if (revision !== undefined && current !== revision) invalidate?.();
  revision = current;
  return current;
}

function onStorage(event: StorageEvent): void {
  if (event.key === MARKER || event.key === null) observeRevision();
}

export function watchKeyLifecycle(onInvalidate: () => void): void {
  if (invalidate) return;
  invalidate = onInvalidate;
  revision = readRevision();
  if (typeof window === 'undefined') return;
  window.addEventListener('storage', onStorage);
  try {
    if (window.BroadcastChannel) {
      channel = new window.BroadcastChannel(CHANNEL);
      channel.onmessage = (event) => {
        if (event.data?.type !== 'key-destroyed') return;
        // Read the current marker, not an older message that arrived late.
        const current = readRevision();
        if (current === null) invalidate?.();
        else observeRevision();
      };
    }
  } catch {
    // The storage event and synchronous revision checks remain available.
  }
}

export function checkKeyLifecycle(expected?: string | null): string | null {
  const current = observeRevision();
  if (expected !== undefined && current !== expected) {
    throw new Error(
      'Secure storage key changed in another tab. Initialize again.',
    );
  }
  if (current) {
    let destroying = false;
    try {
      destroying = JSON.parse(current).destroying === true;
    } catch {
      // An unrelated or malformed marker cannot authorize use of a stale key.
    }
    if (destroying) {
      throw new Error(
        'Secure storage key is being destroyed. Initialize again after it finishes.',
      );
    }
  }
  return current;
}

export function announceKeyDestruction(destroying: boolean): void {
  const next = JSON.stringify({ id: crypto.randomUUID(), destroying });
  // Fail before deleting the key if coordination metadata cannot be written.
  // A full origin must not silently leave another tab using a deleted key.
  globalThis.localStorage.setItem(MARKER, next);
  revision = next;
  channel?.postMessage({ type: 'key-destroyed' });
}

export function stopWatchingKeyLifecycle(): void {
  if (typeof window !== 'undefined')
    window.removeEventListener('storage', onStorage);
  channel?.close();
  channel = undefined;
  invalidate = undefined;
  revision = undefined;
}
