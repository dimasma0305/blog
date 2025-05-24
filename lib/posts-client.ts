// This file contains optimized types and utility functions for client-side use

// Optimized types with optional heavy fields
export type PostOwner = {
  readonly id: string
  readonly name: string
  readonly avatar_url: string
  readonly type: string
  readonly person?: {
    readonly email: string
  }
}

export type PostVerification = {
  readonly state: 'verified' | 'unverified' | 'pending'
  readonly verified_by: string | null
  readonly date: string | null
}

export type Post = {
  readonly id: string
  readonly slug: string
  readonly title: string
  readonly excerpt: string
  content?: string
  readonly createdAt: string
  readonly updatedAt: string
  readonly coverImage: string
  readonly iconEmoji?: string
  readonly categories: readonly string[]
  readonly verification: PostVerification
  readonly owner?: PostOwner
  readonly notionUrl?: string | null
  readonly wordCount?: number
}

// Lightweight post type for lists and previews
export type PostSummary = Pick<Post, 
  | 'id' 
  | 'slug' 
  | 'title' 
  | 'excerpt' 
  | 'createdAt' 
  | 'updatedAt' 
  | 'coverImage' 
  | 'iconEmoji' 
  | 'categories' 
  | 'notionUrl'
>

// Cache for expensive computations
const categoryCache = new Map<string, Set<string>>()
const postsByCategoryCache = new Map<string, Map<string, Post[]>>()

// Optimized utility functions with memoization
export function getAllCategories(posts: readonly Post[]): string[] {
  const cacheKey = posts.map(p => p.id).sort().join(',')
  
  if (categoryCache.has(cacheKey)) {
    return Array.from(categoryCache.get(cacheKey)!)
  }

  const categories = new Set<string>()
  for (const post of posts) {
    for (const category of post.categories) {
      categories.add(category)
    }
  }

  categoryCache.set(cacheKey, categories)
  return Array.from(categories)
}

export function getPostsByCategory(posts: readonly Post[], category: string): Post[] {
  const postsKey = posts.map(p => p.id).sort().join(',')
  
  if (!postsByCategoryCache.has(postsKey)) {
    postsByCategoryCache.set(postsKey, new Map())
  }

  const categoryMap = postsByCategoryCache.get(postsKey)!
  
  if (categoryMap.has(category)) {
    return categoryMap.get(category)!
  }

  const filtered = posts.filter(post => post.categories.includes(category))
  categoryMap.set(category, filtered)
  
  return filtered
}

// Utility functions for posts
export const sortPostsByDate = (posts: readonly Post[], order: 'asc' | 'desc' = 'desc'): Post[] => {
  return [...posts].sort((a, b) => {
    const dateA = new Date(a.createdAt).getTime()
    const dateB = new Date(b.createdAt).getTime()
    return order === 'desc' ? dateB - dateA : dateA - dateB
  })
}

export const getRecentPosts = (posts: readonly Post[], count = 5): Post[] => {
  return sortPostsByDate(posts, 'desc').slice(0, count)
}

export const searchPosts = (posts: readonly Post[], query: string): Post[] => {
  if (!query.trim()) return [...posts]
  
  const searchTerm = query.toLowerCase().trim()
  
  return posts.filter(post => 
    post.title.toLowerCase().includes(searchTerm) ||
    post.excerpt.toLowerCase().includes(searchTerm) ||
    post.categories.some(cat => cat.toLowerCase().includes(searchTerm)) ||
    (post.content && post.content.toLowerCase().includes(searchTerm))
  )
}

// Cache cleanup utility
export const clearPostsCache = (): void => {
  categoryCache.clear()
  postsByCategoryCache.clear()
}

// Sample posts for client-side preview and fallback (keeping minimal for bundle size)
export const samplePosts: readonly Post[] = [
  {
    id: "sample-post-1",
    slug: "sample-post-1",
    title: "Welcome to Your Interactive Blog",
    excerpt: "This is a sample post to demonstrate the blog functionality.",
    content: `<h1>Welcome to Your Interactive Blog</h1>
<p>This is a sample post that demonstrates the functionality of your interactive blog. You can replace this with your own content.</p>
<h2>Features</h2>
<ul>
  <li>Markdown support</li>
  <li>Syntax highlighting</li>
  <li>Categories and tags</li>
  <li>Responsive design</li>
</ul>`,
    createdAt: "2024-05-01T12:00:00.000Z",
    updatedAt: "2024-05-01T12:00:00.000Z",
    coverImage: "/placeholder.svg?height=600&width=1200",
    iconEmoji: "👋",
    categories: ["General", "Introduction"],
    verification: {
      state: "verified",
      verified_by: "Admin",
      date: "2024-05-01T12:00:00.000Z",
    },
  },
  {
    id: "sample-post-2", 
    slug: "sample-post-2",
    title: "How to Format Your Blog Posts",
    excerpt: "Learn how to format your blog posts using Markdown and HTML.",
    content: `<h1>How to Format Your Blog Posts</h1>
<p>This guide will show you how to format your blog posts using Markdown and HTML.</p>
<h2>Markdown Basics</h2>
<p>Markdown is a lightweight markup language that you can use to add formatting elements to plaintext text documents.</p>`,
    createdAt: "2024-05-02T12:00:00.000Z",
    updatedAt: "2024-05-02T12:00:00.000Z",
    coverImage: "/placeholder.svg?height=600&width=1200",
    iconEmoji: "📝",
    categories: ["Tutorial", "Markdown"],
    verification: {
      state: "verified",
      verified_by: "Admin", 
      date: "2024-05-02T12:00:00.000Z",
    },
  }
] as const
