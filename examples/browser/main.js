import {
  destroySecureStorage,
  initializeSecureStorage,
  isSecureStorageInitialized,
  secureLocalStorage,
} from 'bvault-js';

const keyInput = document.querySelector('#storage-key');
const valueInput = document.querySelector('#value');
const status = document.querySelector('#status');
const state = document.querySelector('#state');
const ciphertext = document.querySelector('#ciphertext');
const plaintext = document.querySelector('#plaintext');
const initialize = document.querySelector('#initialize');
const save = document.querySelector('#save');
const read = document.querySelector('#read');
const destroy = document.querySelector('#destroy');

function refresh() {
  const ready = isSecureStorageInitialized();
  state.textContent = ready ? 'Initialized' : 'Not initialized';
  state.classList.toggle('ready', ready);
  initialize.disabled = ready;
  save.disabled = read.disabled = destroy.disabled = !ready;
  ciphertext.textContent =
    localStorage.getItem(`bv1:${keyInput.value.trim()}`) ??
    'Nothing stored under this key.';
}

async function run(action) {
  for (const button of [initialize, save, read, destroy])
    button.disabled = true;
  try {
    await action();
    status.dataset.error = 'false';
  } catch (error) {
    status.textContent = error instanceof Error ? error.message : String(error);
    status.dataset.error = 'true';
  } finally {
    refresh();
  }
}

function storageKey() {
  const key = keyInput.value.trim();
  if (!key) throw new Error('Enter a storage key first.');
  return key;
}

initialize.addEventListener('click', () =>
  run(async () => {
    await initializeSecureStorage();
    status.textContent =
      'Vault initialized. Save an object or read an existing value.';
  }),
);
save.addEventListener('click', () =>
  run(async () => {
    const key = storageKey();
    let value;
    try {
      value = JSON.parse(valueInput.value);
    } catch {
      throw new Error(
        'Enter valid JSON before saving. Your stored value was not changed.',
      );
    }
    await secureLocalStorage.setItem(key, value);
    plaintext.textContent =
      'Saved. Click Read & decrypt to retrieve the value.';
    status.textContent = `Encrypted and saved under “${key}”.`;
  }),
);
read.addEventListener('click', () =>
  run(async () => {
    const key = storageKey();
    const stored = await secureLocalStorage.getItem(key);
    if (stored === null) {
      plaintext.textContent = 'No readable value under this key.';
      status.textContent = 'The value is missing or could not be decrypted.';
      return;
    }
    plaintext.textContent = JSON.stringify(JSON.parse(stored), null, 2);
    status.textContent = `Read and decrypted “${key}”.`;
  }),
);
destroy.addEventListener('click', () =>
  run(async () => {
    await destroySecureStorage();
    plaintext.textContent =
      'Vault destroyed. Its previous values cannot be recovered.';
    status.textContent =
      'Key and bVault values deleted. Initialize to create a new vault.';
  }),
);
keyInput.addEventListener('input', () => {
  refresh();
  plaintext.textContent = 'Click Read & decrypt to retrieve this value.';
});
window.addEventListener('storage', refresh);
refresh();
