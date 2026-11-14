import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const port = Number(process.env.PORT ?? 4173);
const root = new URL('../', import.meta.url);
// Serve only the demo, test fixture, and built package, never the checkout.
const routes = new Map([
  ['/', ['examples/browser/index.html', 'text/html']],
  ['/examples/browser/', ['examples/browser/index.html', 'text/html']],
  [
    '/examples/browser/main.js',
    ['examples/browser/main.js', 'text/javascript'],
  ],
  ['/examples/browser/styles.css', ['examples/browser/styles.css', 'text/css']],
  ['/dist/bvault.min.js', ['dist/bvault.min.js', 'text/javascript']],
  ['/test/browser/', ['test/browser/fixture.html', 'text/html']],
]);

const server = createServer(async (request, response) => {
  const pathname = new URL(request.url ?? '/', 'http://localhost').pathname;
  const route = routes.get(pathname);
  if (!route || !['GET', 'HEAD'].includes(request.method ?? '')) {
    response.writeHead(404).end('Not found');
    return;
  }
  try {
    const content = await readFile(new URL(route[0], root));
    response.writeHead(200, {
      'Content-Type': `${route[1]}; charset=utf-8`,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    response.end(request.method === 'HEAD' ? undefined : content);
  } catch {
    response.writeHead(404).end('Build the package with npm run bundle first.');
  }
});

server.listen(port, '127.0.0.1', () => {
  console.log(`bVault example: http://127.0.0.1:${port}/examples/browser/`);
  console.log(`Serving assets from ${fileURLToPath(root)}`);
});
for (const signal of ['SIGINT', 'SIGTERM'] as const) {
  process.on(signal, () => server.close());
}
