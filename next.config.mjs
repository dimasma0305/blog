/** @type {import('next').NextConfig} */
const nextConfig = {
  pageExtensions: ['js', 'jsx', 'md', 'mdx', 'ts', 'tsx'],
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
    remotePatterns: [
      {
        protocol: 'https',
        hostname: '**',
      },
    ],
  },
  // Add configuration to serve static files from the posts directory
  async rewrites() {
    return [
      {
        source: '/posts/:path*',
        destination: '/api/static/:path*',
      },
    ]
  },
}

export default nextConfig
