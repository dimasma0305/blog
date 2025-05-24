const fs = require('fs')
const path = require('path')

const POSTS_DIR = path.join(process.cwd(), 'public', 'posts')
const ROBOTS_FILE = path.join(process.cwd(), 'public', 'robots.txt')
const BASE_URL = process.env.BASE_URL

function generateRobots() {
  console.log('🤖 Generating robots.txt...')
  
  try {
    // Read the posts index to get categories and other data
    const indexPath = path.join(POSTS_DIR, 'index.json')
    let indexData = null
    
    if (fs.existsSync(indexPath)) {
      const indexContent = fs.readFileSync(indexPath, 'utf8')
      indexData = JSON.parse(indexContent)
      console.log(`📊 Found ${indexData.totalPosts} posts with ${indexData.categories.length} categories`)
    } else {
      console.warn('⚠️  Posts index not found. Generating basic robots.txt')
    }

    // Generate robots.txt content
    const robotsContent = `# Robots.txt for dimasma0305.github.io
# Generated automatically on ${new Date().toISOString()}
# Allow all search engines to crawl the site

User-agent: *
Allow: /

# Important pages for crawling
Allow: /blog
Allow: /posts/
Allow: /categories/
Allow: /about

# Disallow admin and private areas
Disallow: /admin/
Disallow: /api/
Disallow: /_next/
Disallow: /.*

# Allow crawling of static assets
Allow: /images/
Allow: /posts/*/imgs/
Allow: *.css
Allow: *.js
Allow: *.png
Allow: *.jpg
Allow: *.jpeg
Allow: *.gif
Allow: *.svg
Allow: *.webp
Allow: *.ico

# Sitemap location
Sitemap: ${BASE_URL}/sitemap.xml

# Crawl delay (helps prevent overwhelming the server)
Crawl-delay: 1

# Additional user agents configuration
User-agent: Googlebot
Allow: /
Crawl-delay: 1

User-agent: Bingbot
Allow: /
Crawl-delay: 1

User-agent: Slurp
Allow: /
Crawl-delay: 2

# Block known bad bots
User-agent: AhrefsBot
Disallow: /

User-agent: MJ12bot
Disallow: /

User-agent: DotBot
Disallow: /

User-agent: SemrushBot
Disallow: /

User-agent: BLEXBot
Disallow: /`

    // Write robots.txt
    fs.writeFileSync(ROBOTS_FILE, robotsContent)
    
    console.log('✅ Successfully generated robots.txt')
    console.log(`📍 Robots.txt saved to: ${ROBOTS_FILE}`)
    
    // Display summary
    const lines = robotsContent.split('\n')
    const allowRules = lines.filter(line => line.startsWith('Allow:')).length
    const disallowRules = lines.filter(line => line.startsWith('Disallow:')).length
    const userAgents = lines.filter(line => line.startsWith('User-agent:')).length
    
    console.log(`📋 Summary:`)
    console.log(`   - User agents: ${userAgents}`)
    console.log(`   - Allow rules: ${allowRules}`)
    console.log(`   - Disallow rules: ${disallowRules}`)
    console.log(`   - Sitemap URL: ${BASE_URL}/sitemap.xml`)

  } catch (error) {
    console.error('❌ Error generating robots.txt:', error.message)
    process.exit(1)
  }
}

// Run the script
if (require.main === module) {
  generateRobots()
}

module.exports = { generateRobots }
