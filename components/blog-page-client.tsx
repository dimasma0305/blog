"use client"

import { useState, useMemo, useCallback } from "react"
import { usePosts } from "@/hooks/use-posts"
import PostCard from "@/components/post-card"
import { SearchBar } from "@/components/search-bar"
import { Categories } from "@/components/categories"
import { BlogStats } from "@/components/blog-stats"
import { LoadingSpinner } from "@/components/loading-spinner"
import { Button } from "@/components/ui/button"
import { RefreshCw } from "lucide-react"

export default function BlogPageClient() {
  const { posts, loading, refreshing, error, refresh } = usePosts()
  const [searchQuery, setSearchQuery] = useState("")

  // Filter posts based on search query with optimized filtering
  const filteredPosts = useMemo(() => {
    if (!searchQuery.trim()) {
      return posts
    }

    const query = searchQuery.toLowerCase()
    return posts.filter((post) => {
      // Early return for exact title matches
      if (post.title.toLowerCase().includes(query)) return true
      
      // Check other fields
      return (
        post.excerpt.toLowerCase().includes(query) ||
        post.categories.some(category => category.toLowerCase().includes(query)) ||
        post.content.toLowerCase().includes(query)
      )
    })
  }, [posts, searchQuery])

  const handleSearch = useCallback((query: string) => {
    setSearchQuery(query)
  }, [])

  const handleClearSearch = useCallback(() => {
    setSearchQuery("")
  }, [])

  return (
    <div className="container px-4 py-12 mx-auto max-w-7xl">
      <div className="flex items-center justify-between mb-8">
        <div className="flex items-center gap-4">
          <h1 className="text-3xl font-bold tracking-tight">Blog</h1>
          <Button
            variant="outline"
            size="sm"
            onClick={refresh}
            disabled={refreshing}
            className="flex items-center gap-2"
          >
            <RefreshCw className={`h-4 w-4 ${refreshing ? 'animate-spin' : ''}`} />
            Refresh
          </Button>
        </div>
        <SearchBar onSearch={handleSearch} />
      </div>

      {searchQuery && (
        <div className="mb-6 flex items-center gap-2">
          <p className="text-sm text-muted-foreground">
            {filteredPosts.length} result{filteredPosts.length !== 1 ? 's' : ''} for "{searchQuery}"
          </p>
          <button 
            onClick={handleClearSearch}
            className="text-sm text-primary hover:underline"
          >
            Clear search
          </button>
        </div>
      )}

      {error && (
        <div className="mb-6 p-4 bg-destructive/10 border border-destructive/20 rounded-lg">
          <p className="text-destructive text-sm">{error}</p>
          <Button 
            variant="outline" 
            size="sm" 
            onClick={refresh}
            className="mt-2"
          >
            Try Again
          </Button>
        </div>
      )}

      <div className="flex flex-col gap-8 lg:flex-row">
        <div className="w-full lg:w-3/4">
          {loading ? (
            <div className="flex flex-col items-center justify-center py-12">
              <LoadingSpinner />
              <p className="text-sm text-muted-foreground mt-4">Loading posts...</p>
            </div>
          ) : filteredPosts.length > 0 ? (
            <>
              <div className="grid gap-8 sm:grid-cols-2 xl:grid-cols-3">
                {filteredPosts.map((post) => (
                  <PostCard key={post.id} post={post} />
                ))}
              </div>
              {posts.length > filteredPosts.length && (
                <div className="mt-8 text-center">
                  <p className="text-sm text-muted-foreground">
                    Showing {filteredPosts.length} of {posts.length} posts
                  </p>
                </div>
              )}
            </>
          ) : searchQuery ? (
            <div className="text-center py-12">
              <p className="text-muted-foreground">No posts found matching "{searchQuery}".</p>
              <button 
                onClick={handleClearSearch}
                className="mt-2 text-primary hover:underline"
              >
                Clear search to see all posts
              </button>
            </div>
          ) : (
            <div className="text-center py-12">
              <p className="text-muted-foreground">No posts found. Add markdown files to the /posts directory.</p>
            </div>
          )}
        </div>
        
        <div className="w-full lg:w-1/4 space-y-6">
          <BlogStats />
          <Categories posts={filteredPosts} />
        </div>
      </div>
    </div>
  )
} 