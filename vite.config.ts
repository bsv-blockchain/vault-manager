import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig(({ command, mode }) => {
  const isDev = command === 'serve'
  
  return {
    // Entry point - Vite automatically looks for index.html in root or public
    root: '.',
    
    // Public directory (equivalent to CopyWebpackPlugin)
    publicDir: 'public',
    
    // Build configuration
    build: {
      outDir: 'build', // Changed from 'dist' to match webpack.common.js
      emptyOutDir: true,
      sourcemap: isDev ? 'inline' : false,
      rollupOptions: {
        output: {
          entryFileNames: 'bundle.js', // Match webpack output filename
        }
      }
    },
    
    // Development server configuration
    server: {
      port: 8090,
      open: true,
      host: true
    },
    
    // Preview server (for production build testing)
    preview: {
      port: 8090,
      open: true
    },
    
    // Resolve configuration
    resolve: {
      extensions: ['.ts', '.tsx', '.js', '.jsx'],
      alias: {
        // Add any path aliases you might need
        '@': resolve(__dirname, 'src')
      }
    },
    
    // Define global constants (if needed)
    define: {
      // Add any global definitions here
      // 'process.env.NODE_ENV': JSON.stringify(mode)
    },
    
    // CSS configuration
    css: {
      preprocessorOptions: {
        scss: {
          // Add any SCSS options here
        }
      }
    },
    
    // Optimizations and dependencies
    optimizeDeps: {
      // Include dependencies that need pre-bundling
      include: []
    },
    
    // Node.js polyfills (Vite handles most automatically, but you can add specific ones)
    // Note: Most Node.js polyfills are not needed in Vite as it's more modern
    // If you specifically need polyfills, you can use @esbuild-plugins/node-polyfills
  }
})