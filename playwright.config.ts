import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './test/browser',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL: 'http://127.0.0.1:4173',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [
    { name: 'chromium', use: { ...devices['Desktop Chrome'] } },
    {
      name: 'firefox',
      use: {
        ...devices['Desktop Firefox'],
        // Firefox otherwise waits for an unanswered persistent-storage prompt
        // in headless mode. Exercise the supported denial path with native
        // IndexedDB and Web Crypto intact.
        launchOptions: {
          firefoxUserPrefs: { 'permissions.default.persistent-storage': 2 },
        },
      },
    },
    { name: 'webkit', use: { ...devices['Desktop Safari'] } },
  ],
  webServer: {
    command: 'npm run bundle && node scripts/browser-server.mts',
    url: 'http://127.0.0.1:4173/test/browser/',
    reuseExistingServer: false,
    timeout: 60_000,
  },
});
