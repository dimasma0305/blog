// This file provides optimized functions to load posts client-side from public directory

import type { Post } from "./posts-client"
import matter from "gray-matter"
import { remark } from "remark"
import remarkGfm from "remark-gfm"
import remarkRehype from "remark-rehype"
import rehypeSlug from "rehype-slug"
import rehypeAutolinkHeadings from "rehype-autolink-headings"
import rehypeStringify from "rehype-stringify"
import rehypePrism from "rehype-prism-plus"

// Interface for the new index.json structure
interface PostIndex {
  generated: string
  version: string
  totalPosts: number
  categories: string[]
  posts: Post[]
  errors?: Array<{ slug: string; error: string }>
  postsWithNotionLinks?: number
}

// Cache for storing processed posts
interface PostCache {
  posts: Post[]
  timestamp: number
  version: string
}

const CACHE_KEY = "blog_posts_cache_v2" // Updated cache key for new structure
const CACHE_DURATION = 10 * 60 * 1000 // 10 minutes in milliseconds (increased since we load from index)
const CACHE_VERSION = "2.0" // Updated version for new structure

// Memory cache for current session
let memoryCache: { posts: Post[]; timestamp: number; indexVersion?: string } | null = null

// Function to get cached posts from localStorage
function getCachedPosts(): Post[] | null {
  try {
    const cached = localStorage.getItem(CACHE_KEY)
    if (!cached) return null

    const cacheData: PostCache = JSON.parse(cached)
    const now = Date.now()
    
    // Check if cache is expired or version mismatch
    if (
      now - cacheData.timestamp > CACHE_DURATION || 
      cacheData.version !== CACHE_VERSION
    ) {
      localStorage.removeItem(CACHE_KEY)
      return null
    }

    return cacheData.posts
  } catch (error) {
    console.error("Error reading cache:", error)
    localStorage.removeItem(CACHE_KEY)
    return null
  }
}

// Function to cache posts in localStorage
function setCachedPosts(posts: Post[], indexVersion?: string): void {
  try {
    const cacheData: PostCache = {
      posts,
      timestamp: Date.now(),
      version: CACHE_VERSION
    }
    localStorage.setItem(CACHE_KEY, JSON.stringify(cacheData))
  } catch (error) {
    console.error("Error setting cache:", error)
    // Silently fail if localStorage is not available
  }
}

// Function to fetch posts with optimized loading from comprehensive index
export async function fetchAllPosts(): Promise<Post[]> {
  // Check memory cache first (fastest)
  if (memoryCache && Date.now() - memoryCache.timestamp < CACHE_DURATION) {
    return memoryCache.posts
  }

  // Check localStorage cache (fast)
  const cachedPosts = getCachedPosts()
  if (cachedPosts) {
    // Update memory cache
    memoryCache = { posts: cachedPosts, timestamp: Date.now() }
    return cachedPosts
  }

  try {
    console.log("📖 Loading posts from index...")
    
    // Fetch the comprehensive index with all post metadata
    const response = await fetch("/posts/index.json")
    if (!response.ok) {
      throw new Error("Failed to fetch posts index")
    }
    
    const indexData: PostIndex = await response.json()
    
    console.log(`✅ Loaded ${indexData.totalPosts} posts from index (v${indexData.version})`)
    
    // The posts are already processed in the index, just return them
    const sortedPosts = indexData.posts.sort((a, b) => 
      new Date(b.createdAt) > new Date(a.createdAt) ? 1 : -1
    )

    // Cache the results
    setCachedPosts(sortedPosts, indexData.version)
    memoryCache = { 
      posts: sortedPosts, 
      timestamp: Date.now(),
      indexVersion: indexData.version
    }

    return sortedPosts
  } catch (error) {
    console.error("Error fetching posts from index:", error)
    console.log("🔄 Falling back to individual post loading...")
    
    // Fallback to the old method if index fails
    return fetchPostsIndividually()
  }
}

// Fallback function for individual post loading (legacy support)
async function fetchPostsIndividually(): Promise<Post[]> {
  try {
    // Try to get the old simple index format
    const response = await fetch("/posts/index.json")
    if (!response.ok) {
      throw new Error("Failed to fetch posts index")
    }
    
    const data = await response.json()
    
    // Check if it's the new format or old format
    if (data.posts && Array.isArray(data.posts)) {
      // New format, but probably corrupted, return empty for now
      return []
    }
    
    // Old format - array of slugs
    const postSlugs: string[] = Array.isArray(data) ? data : []
    
    // Process posts in batches to avoid blocking the UI
    const BATCH_SIZE = 3
    const allPosts: Post[] = []
    
    for (let i = 0; i < postSlugs.length; i += BATCH_SIZE) {
      const batch = postSlugs.slice(i, i + BATCH_SIZE)
      const batchPosts = await Promise.all(
        batch.map(async (slug) => {
          try {
            return await fetchPostBySlug(slug)
          } catch (error) {
            console.error(`Error fetching post ${slug}:`, error)
            return null
          }
        })
      )
      
      // Add valid posts to the array
      allPosts.push(...batchPosts.filter((post): post is Post => post !== null))
      
      // Small delay between batches to keep UI responsive
      if (i + BATCH_SIZE < postSlugs.length) {
        await new Promise(resolve => setTimeout(resolve, 10))
      }
    }

    // Sort posts by creation date
    return allPosts.sort((a, b) => 
      new Date(b.createdAt) > new Date(a.createdAt) ? 1 : -1
    )
  } catch (error) {
    console.error("Error in fallback post loading:", error)
    return []
  }
}

// Function to fetch a post's full content (including processed markdown)
export async function fetchPostBySlug(slug: string): Promise<Post | null> {
  try {
    // First, try to get the post from the index if available
    if (memoryCache && memoryCache.posts) {
      const postFromIndex = memoryCache.posts.find(p => p.slug === slug)
      if (postFromIndex && postFromIndex.content) {
        return postFromIndex
      }
    }

    // If not in memory or content not available, fetch and process the markdown
    const response = await fetch(`/posts/${slug}/README.md`)
    if (!response.ok) {
      throw new Error(`Failed to fetch post ${slug}`)
    }
    
    const rawContent = await response.text()

    // Parse the frontmatter
    const { data, content } = matter(rawContent)

    // Process the markdown content with syntax highlighting
    const processedContent = await remark()
      .use(remarkGfm)
      .use(remarkRehype, { allowDangerousHtml: true })
      .use(rehypeSlug)
      .use(rehypeAutolinkHeadings)
      .use(rehypePrism, { showLineNumbers: true })
      .use(rehypeStringify, { allowDangerousHtml: true })
      .process(content)

    const contentHtml = processedContent.toString()

    // Process image paths to point to public directory
    const processedHtml = contentHtml.replace(
      /<img([^>]*)src="([^"]*)"([^>]*)>/g,
      (match, before, imgPath, after) => {
        let normalizedSrc = imgPath
        if (imgPath.startsWith("./")) {
          normalizedSrc = `/posts/${slug}/${imgPath.replace("./", "")}`
        } else if (!imgPath.startsWith("/") && !imgPath.startsWith("http")) {
          normalizedSrc = `/posts/${slug}/${imgPath}`
        }

        return `<img${before}src="${normalizedSrc}"${after} 
          class="rounded-lg my-8" 
          loading="lazy" 
          onerror="this.onerror=null;this.src='/placeholder.svg?height=400&width=600&text=Image%20Not%20Found'">`
      }
    )

    // Extract the first paragraph as excerpt
    const excerpt = content
      .split("\n\n")[0]
      .replace(/^#+\s+/, "")
      .trim()

    // Process cover image path
    let coverImage = data.cover_image || ""
    if (coverImage && coverImage.startsWith("./")) {
      coverImage = coverImage.replace("./", `/posts/${slug}/`)
    }

    // Create post object
    return {
      id: data.id || slug,
      slug,
      title: data.title || "Untitled",
      excerpt,
      content: processedHtml,
      createdAt: data.created_time || new Date().toISOString(),
      updatedAt: data.last_edited_time || new Date().toISOString(),
      coverImage,
      iconEmoji: data.icon_emoji || "",
      categories: data.categories || [],
      verification: data.verification || {
        state: "unverified",
        verified_by: null,
        date: null,
      },
      owner: data.owner || undefined,
    }
  } catch (error) {
    console.error(`Error processing post ${slug}:`, error)
    return null
  }
}

// Function to prefetch posts in the background
export function prefetchPosts(): void {
  // Use requestIdleCallback for background fetching
  if ('requestIdleCallback' in window) {
    requestIdleCallback(() => {
      fetchAllPosts().catch(console.error)
    })
  } else {
    // Fallback for browsers without requestIdleCallback
    setTimeout(() => {
      fetchAllPosts().catch(console.error)
    }, 100)
  }
}

// Function to invalidate cache (useful for refresh)
export function invalidateCache(): void {
  localStorage.removeItem(CACHE_KEY)
  // Also remove old cache key if it exists
  localStorage.removeItem("blog_posts_cache")
  memoryCache = null
}

// Function to get blog statistics from index
export async function getBlogStats(): Promise<{
  totalPosts: number
  categories: string[]
  lastGenerated: string
  postsWithNotionLinks: number
} | null> {
  try {
    const response = await fetch("/posts/index.json")
    if (!response.ok) return null
    
    const indexData: PostIndex = await response.json()
    
    return {
      totalPosts: indexData.totalPosts,
      categories: indexData.categories,
      lastGenerated: indexData.generated,
      postsWithNotionLinks: indexData.postsWithNotionLinks || 0
    }
  } catch (error) {
    console.error("Error fetching blog stats:", error)
    return null
  }
}

// Function to get all posts (alias for fetchAllPosts for compatibility)
export async function getAllPosts(): Promise<Post[]> {
  return fetchAllPosts()
}

// Function to get a post by slug (alias for fetchPostBySlug for compatibility)  
export async function getPostBySlug(slug: string): Promise<Post | null> {
  return fetchPostBySlug(slug)
}
