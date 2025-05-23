import CategoryPageClient from "@/components/category-page-client"

// Generate static params for all categories
export async function generateStaticParams() {
  try {
    // Read the comprehensive index file directly from the file system during build
    const fs = require('fs')
    const path = require('path')
    
    const indexPath = path.join(process.cwd(), 'public', 'posts', 'index.json')
    const indexContent = fs.readFileSync(indexPath, 'utf8')
    const indexData = JSON.parse(indexContent)
    
    // Check if it's the new comprehensive format or old format
    let categories: string[] = []
    
    if (indexData.categories && Array.isArray(indexData.categories)) {
      // New comprehensive format - categories are already extracted
      categories = indexData.categories
      console.log(`📁 Generated static params for ${categories.length} categories from comprehensive index`)
    } else if (Array.isArray(indexData)) {
      // Old format - need to extract categories from posts
      console.log('📁 Using legacy method to extract categories...')
      const matter = require('gray-matter')
      const categoriesSet = new Set<string>()
      
      for (const slug of indexData) {
        try {
          const readmePath = path.join(process.cwd(), 'public', 'posts', slug, 'README.md')
          const fileContents = fs.readFileSync(readmePath, 'utf8')
          const { data } = matter(fileContents)
          
          if (data.categories && Array.isArray(data.categories)) {
            data.categories.forEach((category: string) => {
              categoriesSet.add(category)
            })
          }
        } catch (error) {
          console.error(`Error reading post ${slug}:`, error)
        }
      }
      
      categories = Array.from(categoriesSet)
    } else if (indexData.posts && Array.isArray(indexData.posts)) {
      // New format but no pre-extracted categories - extract from posts
      const categoriesSet = new Set<string>()
      
      indexData.posts.forEach((post: any) => {
        if (post.categories && Array.isArray(post.categories)) {
          post.categories.forEach((category: string) => {
            categoriesSet.add(category)
          })
        }
      })
      
      categories = Array.from(categoriesSet)
    }
    
    return categories.map((category) => ({
      category: category,
    }))
  } catch (error) {
    console.error('Error generating static params for categories:', error)
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
      
      const categories = indexData.categories || []
      console.log(`✅ Generated index and static params for ${categories.length} categories`)
      
      return categories.map((category: string) => ({
        category: category,
      }))
    } catch (generateError) {
      console.error('Failed to generate index:', generateError)
      // Fallback: return common categories
      return [
        { category: 'wordpress' },
        { category: 'XSS' },
        { category: 'XXE' },
        { category: 'CSS Leak' },
        { category: 'Domclobering' },
      ]
    }
  }
}

interface CategoryPageProps {
  params: Promise<{
    category: string
  }>
}

export default async function CategoryPage({ params }: CategoryPageProps) {
  const { category } = await params
  return <CategoryPageClient category={category} />
}
