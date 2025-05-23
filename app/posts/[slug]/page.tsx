import PostPageClient from "@/components/post-page-client"
import { generatePostMetadata } from "@/components/seo"
import { Metadata } from "next"

// Generate static params for all posts
export async function generateStaticParams() {
  try {
    // Read the comprehensive index file directly from the file system during build
    const fs = require('fs')
    const path = require('path')
    
    const indexPath = path.join(process.cwd(), 'public', 'posts', 'index.json')
    const indexContent = fs.readFileSync(indexPath, 'utf8')
    const indexData = JSON.parse(indexContent)
    
    // Check if it's the new comprehensive format or old format
    let slugs: string[] = []
    
    if (indexData.posts && Array.isArray(indexData.posts)) {
      // New comprehensive format
      slugs = indexData.posts.map((post: any) => post.slug)
      console.log(`📝 Generated static params for ${slugs.length} posts from comprehensive index`)
    } else if (Array.isArray(indexData)) {
      // Old format (array of slugs)
      slugs = indexData
      console.log(`📝 Generated static params for ${slugs.length} posts from legacy index`)
    }
    
    return slugs.map((slug) => ({
      slug: slug,
    }))
  } catch (error) {
    console.error('Error generating static params:', error)
    console.log('🔄 Attempting to generate index.json...')
    
    // Try to generate the index if it doesn't exist
    try {
      const { generateIndex } = require('../../../scripts/generate-index')
      generateIndex()
      
      // Try again after generating
      const fs = require('fs')
      const path = require('path')
      const indexPath = path.join(process.cwd(), 'public', 'posts', 'index.json')
      const indexContent = fs.readFileSync(indexPath, 'utf8')
      const indexData = JSON.parse(indexContent)
      
      const slugs = indexData.posts ? indexData.posts.map((post: any) => post.slug) : []
      console.log(`✅ Generated index and static params for ${slugs.length} posts`)
      
      return slugs.map((slug: string) => ({
        slug: slug,
      }))
    } catch (generateError) {
      console.error('Failed to generate index:', generateError)
      return []
    }
  }
}

// Generate metadata for each post
export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  try {
    const { slug } = await params
    
    // Read the post data from the index for metadata generation
    const fs = require('fs')
    const path = require('path')
    
    const indexPath = path.join(process.cwd(), 'public', 'posts', 'index.json')
    const indexContent = fs.readFileSync(indexPath, 'utf8')
    const indexData = JSON.parse(indexContent)
    
    // Find the post in the index
    let post = null
    if (indexData.posts && Array.isArray(indexData.posts)) {
      post = indexData.posts.find((p: any) => p.slug === slug)
    }
    
    if (!post) {
      // Fallback metadata for posts not found in index
      return {
        title: 'Post Not Found',
        description: 'The requested blog post could not be found.',
      }
    }
    
    // Generate SEO metadata for the post
    return generatePostMetadata({ post })
  } catch (error) {
    console.error('Error generating metadata:', error)
    return {
      title: 'Blog Post',
      description: 'A blog post by Dimas Maulana',
    }
  }
}

interface PostPageProps {
  params: Promise<{
    slug: string
  }>
}

export default async function PostPage({ params }: PostPageProps) {
  const { slug } = await params
  return <PostPageClient slug={slug} />
}
