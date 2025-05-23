import { useState, useEffect, useCallback } from "react"
import { fetchAllPosts, prefetchPosts, invalidateCache } from "@/lib/posts-loader"
import type { Post } from "@/lib/posts-client"

interface UsePostsReturn {
  posts: Post[]
  loading: boolean
  refreshing: boolean
  error: string | null
  refresh: () => void
  clearError: () => void
}

export function usePosts(): UsePostsReturn {
  const [posts, setPosts] = useState<Post[]>([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const loadPosts = useCallback(async (isRefresh = false) => {
    try {
      if (isRefresh) {
        setRefreshing(true)
        invalidateCache()
      }
      
      const allPosts = await fetchAllPosts()
      setPosts(allPosts)
      setError(null)
    } catch (err) {
      console.error("Error loading posts:", err)
      setError("Failed to load posts. Please try again.")
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }, [])

  const refresh = useCallback(() => {
    loadPosts(true)
  }, [loadPosts])

  const clearError = useCallback(() => {
    setError(null)
  }, [])

  useEffect(() => {
    loadPosts()
  }, [loadPosts])

  // Prefetch posts for better performance
  useEffect(() => {
    prefetchPosts()
  }, [])

  return {
    posts,
    loading,
    refreshing,
    error,
    refresh,
    clearError,
  }
} 