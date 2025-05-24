import { useState, useEffect, useCallback, useRef, useMemo } from "react"
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

interface PostsState {
  posts: Post[]
  loading: boolean
  refreshing: boolean
  error: string | null
}

// Shared cache and request deduplication
let sharedPostsCache: Post[] | null = null
let requestInProgress = false
let pendingCallbacks: ((posts: Post[]) => void)[] = []

export function usePosts(): UsePostsReturn {
  const [state, setState] = useState<PostsState>({
    posts: sharedPostsCache || [],
    loading: !sharedPostsCache,
    refreshing: false,
    error: null,
  })

  const mountedRef = useRef(true)
  const abortControllerRef = useRef<AbortController | null>(null)

  // Optimized state updater
  const updateState = useCallback((update: Partial<PostsState>) => {
    if (mountedRef.current) {
      setState(prev => ({ ...prev, ...update }))
    }
  }, [])

  // Load posts with request deduplication
  const loadPosts = useCallback(async (isRefresh = false) => {
    // Request deduplication
    if (requestInProgress && !isRefresh) {
      return new Promise<Post[]>((resolve) => {
        pendingCallbacks.push(resolve)
      })
    }

    // Cancel existing request
    if (abortControllerRef.current) {
      abortControllerRef.current.abort()
    }

    abortControllerRef.current = new AbortController()

    try {
      requestInProgress = true
      
      updateState({ 
        [isRefresh ? 'refreshing' : 'loading']: true, 
        error: null 
      })

      if (isRefresh) {
        invalidateCache()
        sharedPostsCache = null
      }

      const allPosts = await fetchAllPosts()

      if (mountedRef.current && !abortControllerRef.current.signal.aborted) {
        sharedPostsCache = allPosts
        updateState({
          posts: allPosts,
          loading: false,
          refreshing: false,
          error: null,
        })

        // Resolve pending callbacks
        pendingCallbacks.forEach(callback => callback(allPosts))
        pendingCallbacks = []
      }

      return allPosts
    } catch (err) {
      if (!abortControllerRef.current?.signal.aborted && mountedRef.current) {
        const errorMessage = err instanceof Error ? err.message : "Failed to load posts"
        updateState({
          loading: false,
          refreshing: false,
          error: errorMessage,
        })
      }
      throw err
    } finally {
      requestInProgress = false
    }
  }, [updateState])

  const refresh = useCallback(() => {
    loadPosts(true).catch(() => {})
  }, [loadPosts])

  const clearError = useCallback(() => {
    updateState({ error: null })
  }, [updateState])

  // Initial load
  useEffect(() => {
    if (sharedPostsCache?.length) {
      updateState({ posts: sharedPostsCache, loading: false })
      return
    }

    loadPosts().catch(() => {})
  }, [loadPosts, updateState])

  // Prefetch optimization
  useEffect(() => {
    const timer = setTimeout(prefetchPosts, 100)
    return () => clearTimeout(timer)
  }, [])

  // Cleanup
  useEffect(() => {
    return () => {
      mountedRef.current = false
      abortControllerRef.current?.abort()
    }
  }, [])

  return useMemo(() => ({
    posts: state.posts,
    loading: state.loading,
    refreshing: state.refreshing,
    error: state.error,
    refresh,
    clearError,
  }), [state, refresh, clearError])
}
