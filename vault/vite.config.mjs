import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { viteSingleFile } from 'vite-plugin-singlefile'

export default defineConfig({
  plugins: [react(), viteSingleFile()],
  css: {
    preprocessorOptions: {
      scss: {
        api: 'modern-compiler'
      }
    }
  },
  build: {
    outDir: 'build',
    assetsInlineLimit: 100000000, // Inline all assets regardless of size
    cssCodeSplit: false, // Keep all CSS in a single bundle
    rollupOptions: {
      output: {
        inlineDynamicImports: true // Inline the QR scanner worker
      }
    }
  },
  server: {
    host: "::",
    port: 8080
  }
})