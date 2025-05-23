/** @type {import('next').NextConfig} */
const nextConfig = {
  output: 'export',
  
  // GitHub Pages configuration
  basePath: process.env.NODE_ENV === 'production' ? '' : '',
  assetPrefix: process.env.NODE_ENV === 'production' ? '' : '',
  
  // Disable server-side features for static export
  trailingSlash: true,
  images: {
    unoptimized: true,
  },
  
  // Generate static files
  distDir: 'out',
  
  // Disable strict mode for better compatibility
  reactStrictMode: false,
  
  // Optimize for development
  swcMinify: process.env.NODE_ENV === 'production',
  
  // Experimental features for better performance
  experimental: {
    turbo: {
      rules: {
        '*.json': {
          loaders: ['raw-loader'],
        },
      },
    },
  },
  
  // Webpack configuration for better GitHub Pages compatibility
  webpack: (config, { isServer, dev }) => {
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        path: false,
      }
    }

    // Development optimizations
    if (dev) {
      // Ignore files that shouldn't trigger rebuilds during development
      config.watchOptions = {
        ...config.watchOptions,
        ignored: [
          '**/node_modules/**',
          '**/.git/**',
          '**/public/posts/index.json',
          '**/public/sitemap.xml',
          '**/out/**',
          '**/.next/**',
          '**/scripts/generate-*.js',
          '**/*.tmp',
          '**/*.swp',
          '**/*~',
        ],
        // Reduce CPU usage by polling less frequently
        poll: 1000,
        aggregateTimeout: 300,
      }

      // Optimize for faster rebuilds
      config.cache = {
        type: 'filesystem',
        allowCollectingMemory: true,
      }
    }

    return config
  },

  // Enable source maps only in development
  productionBrowserSourceMaps: false,
}

module.exports = nextConfig 