#!/usr/bin/env node

const fs = require('fs')
const path = require('path')

const POSTS_DIR = path.join(process.cwd(), 'public', 'posts')
const SITEMAP_FILE = path.join(process.cwd(), 'public', 'sitemap.xml')
const BASE_URL = 'https://dimasma0305.github.io'

function formatDate(date) {
  return new Date(date).toISOString().split('T')[0]
}

function generateSitemap() {
  console.log('🗺️  Generating sitemap...')
  
  try {
    // Read the posts index
    const indexPath = path.join(POSTS_DIR, 'index.json')
    if (!fs.existsSync(indexPath)) {
      console.error('❌ Posts index not found. Run generate-index first.')
      process.exit(1)
    }

    const indexContent = fs.readFileSync(indexPath, 'utf8')
    const indexData = JSON.parse(indexContent)

    // Static pages
    const staticPages = [
      {
        url: BASE_URL,
        lastmod: new Date().toISOString().split('T')[0],
        changefreq: 'weekly',
        priority: '1.0'
      },
      {
        url: `${BASE_URL}/blog`,
        lastmod: formatDate(indexData.generated),
        changefreq: 'weekly',
        priority: '0.9'
      },
      {
        url: `${BASE_URL}/about`,
        lastmod: new Date().toISOString().split('T')[0],
        changefreq: 'monthly',
        priority: '0.7'
      }
    ]

    // Add category pages
    const categoryPages = indexData.categories.map(category => ({
      url: `${BASE_URL}/categories/${encodeURIComponent(category)}`,
      lastmod: formatDate(indexData.generated),
      changefreq: 'weekly',
      priority: '0.6'
    }))

    // Add blog posts
    const postPages = indexData.posts.map(post => ({
      url: `${BASE_URL}/posts/${post.slug}`,
      lastmod: formatDate(post.updatedAt || post.createdAt),
      changefreq: 'monthly',
      priority: '0.8'
    }))

    // Combine all pages
    const allPages = [...staticPages, ...categoryPages, ...postPages]

    // Generate XML
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:news="http://www.google.com/schemas/sitemap-news/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml"
        xmlns:mobile="http://www.google.com/schemas/sitemap-mobile/1.0"
        xmlns:image="http://www.google.com/schemas/sitemap-image/1.1"
        xmlns:video="http://www.google.com/schemas/sitemap-video/1.1">
${allPages.map(page => `  <url>
    <loc>${page.url}</loc>
    <lastmod>${page.lastmod}</lastmod>
    <changefreq>${page.changefreq}</changefreq>
    <priority>${page.priority}</priority>
  </url>`).join('\n')}
</urlset>`

    // Write sitemap
    fs.writeFileSync(SITEMAP_FILE, xml)
    
    console.log(`✅ Generated sitemap with ${allPages.length} URLs`)
    console.log(`   - Static pages: ${staticPages.length}`)
    console.log(`   - Category pages: ${categoryPages.length}`)
    console.log(`   - Blog posts: ${postPages.length}`)
    console.log(`📍 Sitemap saved to: ${SITEMAP_FILE}`)

  } catch (error) {
    console.error('❌ Error generating sitemap:', error.message)
    process.exit(1)
  }
}

// Run the script
if (require.main === module) {
  generateSitemap()
}

module.exports = { generateSitemap } 