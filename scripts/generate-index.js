#!/usr/bin/env node

const fs = require('fs')
const path = require('path')
const matter = require('gray-matter')

const POSTS_DIR = path.join(process.cwd(), 'public', 'posts')
const INDEX_FILE = path.join(POSTS_DIR, 'index.json')

// Base Notion URL
const NOTION_BASE_URL = 'https://dimas0305.notion.site'

function extractExcerpt(content) {
  // Extract the first paragraph as excerpt
  const excerpt = content
    .split('\n\n')[0]
    .replace(/^#+\s+/, '') // Remove heading markers
    .replace(/!\[.*?\]\(.*?\)/g, '') // Remove images
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1') // Convert links to plain text
    .trim()
    .substring(0, 200)
  
  return excerpt + (content.length > 200 ? '...' : '')
}

function processPost(slug, readmePath) {
  try {
    const rawContent = fs.readFileSync(readmePath, 'utf8')
    const { data, content } = matter(rawContent)

    // Process cover image path
    let coverImage = data.cover_image || ''
    if (coverImage && coverImage.startsWith('./')) {
      coverImage = coverImage.replace('./', `/posts/${slug}/`)
    }

    // Extract excerpt
    const excerpt = extractExcerpt(content)

    // Calculate estimated reading time (average 200 words per minute)
    const wordCount = content.split(/\s+/).length
    const readingTime = Math.ceil(wordCount / 200)

    // Generate Notion URL from post ID
    let notionUrl = null
    if (data.id) {
      // Remove dashes from UUID and create Notion URL
      const notionId = data.id.replace(/-/g, '')
      notionUrl = `${NOTION_BASE_URL}/${notionId}`
    }

    return {
      id: data.id || slug,
      slug,
      title: data.title || 'Untitled',
      excerpt,
      createdAt: data.created_time || new Date().toISOString(),
      updatedAt: data.last_edited_time || new Date().toISOString(),
      coverImage,
      iconEmoji: data.icon_emoji || '',
      categories: data.categories || [],
      verification: data.verification || {
        state: 'unverified',
        verified_by: null,
        date: null,
      },
      owner: data.owner || undefined,
      readingTime,
      wordCount,
      hasImages: content.includes('![') || content.includes('<img'),
      hasCode: content.includes('```') || content.includes('<code>'),
      notionUrl, // Add Notion URL
    }
  } catch (error) {
    console.error(`Error processing post ${slug}:`, error.message)
    return null
  }
}

function generateIndex() {
  console.log('🔍 Scanning posts directory...')
  
  if (!fs.existsSync(POSTS_DIR)) {
    console.error('❌ Posts directory not found:', POSTS_DIR)
    process.exit(1)
  }

  const entries = fs.readdirSync(POSTS_DIR, { withFileTypes: true })
  const postDirs = entries
    .filter(entry => entry.isDirectory())
    .map(entry => entry.name)

  console.log(`📝 Found ${postDirs.length} post directories`)

  const posts = []
  const errors = []

  for (const slug of postDirs) {
    const readmePath = path.join(POSTS_DIR, slug, 'README.md')
    
    if (!fs.existsSync(readmePath)) {
      console.warn(`⚠️  No README.md found for post: ${slug}`)
      errors.push({ slug, error: 'No README.md found' })
      continue
    }

    const post = processPost(slug, readmePath)
    if (post) {
      posts.push(post)
      const notionStatus = post.notionUrl ? '🔗' : '❌'
      console.log(`✅ Processed: ${post.title} ${notionStatus}`)
    } else {
      errors.push({ slug, error: 'Failed to process' })
    }
  }

  // Sort posts by creation date (newest first)
  posts.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))

  // Count posts with Notion URLs
  const postsWithNotion = posts.filter(post => post.notionUrl).length

  // Create index object with metadata
  const indexData = {
    generated: new Date().toISOString(),
    version: '2.0',
    totalPosts: posts.length,
    postsWithNotionLinks: postsWithNotion,
    categories: [...new Set(posts.flatMap(post => post.categories))].sort(),
    posts,
    errors: errors.length > 0 ? errors : undefined
  }

  // Write the index file
  try {
    fs.writeFileSync(INDEX_FILE, JSON.stringify(indexData, null, 2))
    console.log(`\n🎉 Successfully generated index.json with ${posts.length} posts`)
    console.log(`🔗 ${postsWithNotion} posts have Notion links`)
    console.log(`📁 Categories found: ${indexData.categories.join(', ')}`)
    
    if (errors.length > 0) {
      console.log(`\n⚠️  ${errors.length} errors encountered:`)
      errors.forEach(({ slug, error }) => {
        console.log(`   - ${slug}: ${error}`)
      })
    }
  } catch (error) {
    console.error('❌ Failed to write index.json:', error.message)
    process.exit(1)
  }
}

// Run the script
if (require.main === module) {
  generateIndex()
}

module.exports = { generateIndex } 