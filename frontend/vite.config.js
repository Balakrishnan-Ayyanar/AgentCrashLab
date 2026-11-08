import { defineConfig } from 'vite';

export default defineConfig({
  oxc: { jsx: { runtime: 'automatic' } },
  server: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:8000' } },
  preview: { host: '127.0.0.1', proxy: { '/api': 'http://127.0.0.1:8000' } },
});
