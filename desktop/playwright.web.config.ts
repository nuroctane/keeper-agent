import { defineConfig } from '@playwright/test';
import { existsSync } from 'node:fs';
const python =
  process.env.KEEPER_AGENT_TEST_PYTHON ||
  (process.platform === 'win32' ? '../.venv/Scripts/python.exe' : '../.venv/bin/python');
export default defineConfig({
  testDir: './tests',
  testMatch: 'web.spec.ts',
  workers: 1,
  timeout: 60000,
  expect: { timeout: 10000 },
  use: {
    baseURL: 'http://127.0.0.1:19465',
    viewport: { width: 1320, height: 860 },
    trace: 'retain-on-failure',
  },
  webServer: {
    command: `"${existsSync(python) ? python : 'python'}" tests/web_server.py`,
    url: 'http://127.0.0.1:19465',
    timeout: 60000,
    reuseExistingServer: false,
  },
});
