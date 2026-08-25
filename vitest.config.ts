import path from 'path';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    watch: false,
    passWithNoTests: false,
    isolate: true,
    fileParallelism: false,
    maxWorkers: 1,
    minWorkers: 1,
    retry: 0,
    allowOnly: false,
    sequence: { shuffle: false },
    fakeTimers: { shouldAdvanceTime: false },
  },
  resolve: {
    alias: {
      'cloudflare:workers': path.resolve(__dirname, 'src/__tests__/mocks/cloudflare-workers.ts'),
    },
  },
});
