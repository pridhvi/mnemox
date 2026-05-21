import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  timeout: 60_000,
  expect: {
    timeout: 10_000,
  },
  workers: 1,
  use: {
    ...devices['Desktop Chrome'],
    trace: 'on-first-retry',
  },
});

