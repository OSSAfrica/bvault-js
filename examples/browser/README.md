# Browser playground

A plain HTML example of the 1.0 preview API. No framework or app build is needed.

From the repository root, using Node 24 or newer:

```bash
npm ci
npm run example
```

Open <http://127.0.0.1:4173/examples/browser/>. Keep this origin dedicated to the
demo: **Destroy vault** deletes the encryption key and all bVault values on it.
The sample values stay in your browser. The optional Google Fonts stylesheet is the only
external request; the demo works with fallback fonts offline.

1. Initialize the vault, then save the JSON object.
2. Compare the input with the raw ciphertext displayed from `localStorage`.
3. Click **Read & decrypt** to retrieve and parse the stored JSON string.
4. Reload, initialize, and read again. IndexedDB retains the same key.
5. Destroy the vault to delete its key and encrypted values.

The import map points `bvault-js` to the ESM bundle built from this checkout.
For an app using a bundler, install `npm install bvault-js@preview` and use the
same imports from `bvault-js` as [main.js](main.js).

Web Crypto needs HTTPS or a trustworthy local origin such as `127.0.0.1`.
Opening `index.html` directly with `file://` is not supported.
