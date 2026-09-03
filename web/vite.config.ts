import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
export default defineConfig({plugins:[react()],server:{proxy:{'/api':'http://127.0.0.1:8080','/healthz':'http://127.0.0.1:8080'}},test:{environment:'jsdom',setupFiles:['./src/test-setup.ts'],exclude:['e2e/**','node_modules/**']}});
