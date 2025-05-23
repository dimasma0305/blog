// This file provides optimized functions to load posts client-side from public directory

import type { Post } from "./posts-client"
import { withBasePath } from "./utils"
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

// Shared cache for index data
interface IndexCache {
  data: PostIndex
  timestamp: number
}

const CACHE_KEY = "blog_posts_cache_v2"
const INDEX_CACHE_KEY = "blog_index_cache_v2"
const CACHE_DURATION = 10 * 60 * 1000 // 10 minutes
const CACHE_VERSION = "2.0"

// Memory caches for current session
let memoryCache: { posts: Post[]; timestamp: number; indexVersion?: string } | null = null
let indexMemoryCache: IndexCache | null = null

// Pending requests to avoid duplicate fetches
let pendingIndexRequest: Promise<PostIndex> | null = null
let pendingPostRequests = new Map<string, Promise<Post | null>>()

// Optimized function to get cached posts from localStorage
function getCachedPosts(): Post[] | null {
  try {
    const cached = localStorage.getItem(CACHE_KEY)
    if (!cached) return null

    const cacheData: PostCache = JSON.parse(cached)
    const now = Date.now()
    
    if (now - cacheData.timestamp > CACHE_DURATION || cacheData.version !== CACHE_VERSION) {
      localStorage.removeItem(CACHE_KEY)
      return null
    }

    return cacheData.posts
  } catch (error) {
    console.error("Error reading posts cache:", error)
    localStorage.removeItem(CACHE_KEY)
    return null
  }
}

// Optimized function to get cached index from localStorage
function getCachedIndex(): PostIndex | null {
  try {
    const cached = localStorage.getItem(INDEX_CACHE_KEY)
    if (!cached) return null

    const cacheData: IndexCache = JSON.parse(cached)
    const now = Date.now()
    
    if (now - cacheData.timestamp > CACHE_DURATION) {
      localStorage.removeItem(INDEX_CACHE_KEY)
      return null
    }

    return cacheData.data
  } catch (error) {
    console.error("Error reading index cache:", error)
    localStorage.removeItem(INDEX_CACHE_KEY)
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
    console.error("Error setting posts cache:", error)
  }
}

// Function to cache index in localStorage
function setCachedIndex(indexData: PostIndex): void {
  try {
    const cacheData: IndexCache = {
      data: indexData,
      timestamp: Date.now()
    }
    localStorage.setItem(INDEX_CACHE_KEY, JSON.stringify(cacheData))
  } catch (error) {
    console.error("Error setting index cache:", error)
  }
}

// Optimized function to fetch index with caching and deduplication
async function fetchIndex(): Promise<PostIndex> {
  // Check memory cache first
  if (indexMemoryCache && Date.now() - indexMemoryCache.timestamp < CACHE_DURATION) {
    return indexMemoryCache.data
  }

  // Check localStorage cache
  const cachedIndex = getCachedIndex()
  if (cachedIndex) {
    indexMemoryCache = { data: cachedIndex, timestamp: Date.now() }
    return cachedIndex
  }

  // If there's already a pending request, wait for it
  if (pendingIndexRequest) {
    return pendingIndexRequest
  }

  // Create new request
  pendingIndexRequest = (async () => {
    try {
      const response = await fetch(withBasePath("/posts/index.json"))
      if (!response.ok) {
        throw new Error("Failed to fetch posts index")
      }
      
      const indexData: PostIndex = await response.json()
      
      // Cache the results
      setCachedIndex(indexData)
      indexMemoryCache = { data: indexData, timestamp: Date.now() }
      
      return indexData
    } finally {
      pendingIndexRequest = null
    }
  })()

  return pendingIndexRequest
}

// Optimized function to fetch posts with better caching
export async function fetchAllPosts(): Promise<Post[]> {
  // Check memory cache first (fastest)
  if (memoryCache && Date.now() - memoryCache.timestamp < CACHE_DURATION) {
    return memoryCache.posts
  }

  // Check localStorage cache (fast)
  const cachedPosts = getCachedPosts()
  if (cachedPosts) {
    memoryCache = { posts: cachedPosts, timestamp: Date.now() }
    return cachedPosts
  }

  try {
    console.log("📖 Loading posts from index...")
    
    const indexData = await fetchIndex()
    console.log(`✅ Loaded ${indexData.totalPosts} posts from index (v${indexData.version})`)
    
    // Sort posts by creation date (more efficient sorting)
    const sortedPosts = [...indexData.posts].sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
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
    return fetchPostsIndividually()
  }
}

// Optimized fallback function with better error handling
async function fetchPostsIndividually(): Promise<Post[]> {
  try {
    const indexData = await fetchIndex()
    
    if (!indexData.posts || !Array.isArray(indexData.posts)) {
      return []
    }

    // Process posts in smaller batches for better performance
    const BATCH_SIZE = 2
    const allPosts: Post[] = []
    const slugs = indexData.posts.map(p => p.slug)
    
    for (let i = 0; i < slugs.length; i += BATCH_SIZE) {
      const batch = slugs.slice(i, i + BATCH_SIZE)
      const batchPosts = await Promise.allSettled(
        batch.map(slug => fetchPostBySlug(slug))
      )
      
      // Filter successful results
      batchPosts.forEach((result) => {
        if (result.status === 'fulfilled' && result.value) {
          allPosts.push(result.value)
        }
      })
      
      // Micro-delay for better UX
      if (i + BATCH_SIZE < slugs.length) {
        await new Promise(resolve => setTimeout(resolve, 5))
      }
    }

    return allPosts.sort((a, b) => 
      new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime()
    )
  } catch (error) {
    console.error("Error in fallback post loading:", error)
    return []
  }
}

// Highly optimized function to fetch individual posts with request deduplication
export async function fetchPostBySlug(slug: string): Promise<Post | null> {
  // Check if there's already a pending request for this slug
  if (pendingPostRequests.has(slug)) {
    return pendingPostRequests.get(slug)!
  }

  const fetchPromise = (async (): Promise<Post | null> => {
    try {
      // Check memory cache first
      if (memoryCache?.posts) {
        const postFromCache = memoryCache.posts.find(p => p.slug === slug)
        if (postFromCache?.content) {
          return postFromCache
        }
      }

      // Get index data efficiently (uses shared cache)
      const indexData = await fetchIndex()
      const postFromIndex = indexData.posts?.find(p => p.slug === slug)
      
      if (!postFromIndex) {
        console.warn(`Post ${slug} not found in index`)
        return null
      }

      // If post has content in index, return it directly
      if (postFromIndex.content) {
        return postFromIndex
      }

      // Fetch and process markdown
      const response = await fetch(withBasePath(`/posts/${slug}/README.md`))
      if (!response.ok) {
        throw new Error(`Failed to fetch post ${slug}`)
      }
      
      const rawContent = await response.text()
      const { data, content } = matter(rawContent)

      // Process markdown with optimized settings
      const processedContent = await remark()
        .use(remarkGfm)
        .use(remarkRehype, { allowDangerousHtml: true })
        .use(rehypeSlug)
        .use(rehypeAutolinkHeadings)
        .use(rehypePrism, { showLineNumbers: true })
        .use(rehypeStringify, { allowDangerousHtml: true })
        .process(content)

      // Optimized image processing
      const processedHtml = processedContent.toString().replace(
        /<img([^>]*)src="([^"]*)"([^>]*)>/g,
        (match, before, imgPath, after) => {
          let normalizedSrc = imgPath
          if (imgPath.startsWith("./")) {
            normalizedSrc = withBasePath(`/posts/${slug}/${imgPath.slice(2)}`)
          } else if (!imgPath.startsWith("/") && !imgPath.startsWith("http")) {
            normalizedSrc = withBasePath(`/posts/${slug}/${imgPath}`)
          } else if (imgPath.startsWith("/") && !imgPath.startsWith("http")) {
            normalizedSrc = withBasePath(imgPath)
          } else {
            normalizedSrc = imgPath
          }

          return `<img${before}src="${normalizedSrc}"${after} class="rounded-lg my-8" loading="lazy" onerror="this.onerror=null;this.src='/placeholder.svg?height=400&width=600&text=Image%20Not%20Found'">`
        }
      )

      // Extract excerpt more efficiently
      const excerpt = content.split("\n\n")[0]?.replace(/^#+\s+/, "").trim() || ""

      // Process cover image
      let coverImage = data.cover_image || ""
      if (coverImage?.startsWith("./")) {
        coverImage = withBasePath(`/posts/${slug}/${coverImage.slice(2)}`)
      } else if (coverImage && !coverImage.startsWith("http") && !coverImage.startsWith("/")) {
        coverImage = withBasePath(`/posts/${slug}/${coverImage}`)
      } else if (coverImage?.startsWith("/") && !coverImage.startsWith("http")) {
        coverImage = withBasePath(coverImage)
      }

      // Create optimized post object using index data as base
      const post: Post = {
        ...postFromIndex,
        excerpt,
        content: processedHtml,
        // Override with markdown frontmatter if available
        title: data.title || postFromIndex.title,
        createdAt: data.created_time || postFromIndex.createdAt,
        updatedAt: data.last_edited_time || postFromIndex.updatedAt,
        coverImage: coverImage || postFromIndex.coverImage,
        iconEmoji: data.icon_emoji || postFromIndex.iconEmoji,
        categories: data.categories || postFromIndex.categories,
        verification: data.verification || postFromIndex.verification,
        owner: data.owner || postFromIndex.owner,
      }

      return post
    } catch (error) {
      console.error(`Error processing post ${slug}:`, error)
      return null
    } finally {
      // Clean up pending request
      pendingPostRequests.delete(slug)
    }
  })()

  // Store the promise to avoid duplicate requests
  pendingPostRequests.set(slug, fetchPromise)
  return fetchPromise
}

// Optimized prefetch function
export function prefetchPosts(): void {
  if (typeof window === 'undefined') return
  
  const prefetch = () => fetchAllPosts().catch(console.error)
  
  if ('requestIdleCallback' in window) {
    requestIdleCallback(prefetch, { timeout: 2000 })
  } else {
    setTimeout(prefetch, 100)
  }
}

// Enhanced cache invalidation
export function invalidateCache(): void {
  // Clear localStorage caches
  localStorage.removeItem(CACHE_KEY)
  localStorage.removeItem(INDEX_CACHE_KEY)
  localStorage.removeItem("blog_posts_cache") // Legacy cleanup
  
  // Clear memory caches
  memoryCache = null
  indexMemoryCache = null
  
  // Clear pending requests
  pendingIndexRequest = null
  pendingPostRequests.clear()
}

// Optimized stats function
export async function getBlogStats(): Promise<{
  totalPosts: number
  categories: string[]
  lastGenerated: string
  postsWithNotionLinks: number
} | null> {
  try {
    const indexData = await fetchIndex()
    
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

// Compatibility aliases
export const getAllPosts = fetchAllPosts
export const getPostBySlug = fetchPostBySlug
