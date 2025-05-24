"use client"

import { useEffect, useState } from "react"
import { format } from "date-fns"
import { ArrowLeft, Calendar, Tag, Clock, Share2, Folder } from "lucide-react"
import Link from "next/link"
import { withBasePath } from "@/lib/utils"

import { fetchPostBySlug } from "@/lib/posts-loader"
import { usePosts } from "@/hooks/use-posts"
import type { Post } from "@/lib/posts-client"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Separator } from "@/components/ui/separator"
import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Mdx } from "@/components/mdx"
import { PostNavigation } from "@/components/post-navigation"
import { ShareButtons } from "@/components/share-buttons"
import { FallbackImage } from "@/components/fallback-image"
import { LoadingSpinner } from "@/components/loading-spinner"
import { NotionLinkButton } from "@/components/notion-link-button"
import { TableOfContents } from "@/components/table-of-contents"
import { PostStructuredData } from "@/components/seo"

interface PostPageClientProps {
  slug: string
}

export default function PostPageClient({ slug }: PostPageClientProps) {
  const [post, setPost] = useState<Post | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const { posts } = usePosts()

  useEffect(() => {
    const loadPost = async () => {
      try {
        const fetchedPost = await fetchPostBySlug(slug)
        if (!fetchedPost) {
          setError("Post not found")
          return
        }
        setPost(fetchedPost)
      } catch (err) {
        console.error("Error loading post:", err)
        setError("Failed to load post")
      } finally {
        setLoading(false)
      }
    }

    if (slug) {
      loadPost()
    }
  }, [slug])

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <LoadingSpinner />
      </div>
    )
  }

  if (error || !post) {
    return (
      <div className="container px-4 py-12 mx-auto max-w-7xl">
        <div className="text-center py-12">
          <h1 className="text-2xl font-bold mb-4">Post Not Found</h1>
          <p className="text-muted-foreground mb-4">{error || "The requested post could not be found."}</p>
          <Link href={withBasePath("/blog")}>
            <Button>
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Blog
            </Button>
          </Link>
        </div>
      </div>
    )
  }

  // Calculate reading time
  const estimateReadingTime = (content: string) => {
    const wordsPerMinute = 200
    const words = content.replace(/<[^>]*>/g, "").split(/\s+/).length
    return Math.ceil(words / wordsPerMinute)
  }

  // Get related posts
  const relatedPosts = posts
    .filter((p) => p.id !== post.id && p.categories?.some((cat) => post.categories?.includes(cat)))
    .slice(0, 3)

  return (
    <>
      <PostStructuredData post={post} />

      {/* Hero Section */}
      <div className="bg-gradient-to-b from-muted/30 to-background border-b">
        <div className="container max-w-7xl mx-auto px-4 py-8">
          <div className="max-w-4xl">
            {/* Back Button */}
            <Link href={withBasePath("/blog")}>
              <Button variant="ghost" size="sm" className="mb-6 -ml-2">
                <ArrowLeft className="w-4 h-4 mr-2" />
                Back to all posts
              </Button>
            </Link>

            {/* Categories - Primary Display */}
            {post.categories && post.categories.length > 0 && (
              <div className="mb-6">
                <div className="flex items-center gap-2 mb-3">
                  <Folder className="w-4 h-4 text-muted-foreground" />
                  <span className="text-sm font-medium text-muted-foreground">Categories</span>
                </div>
                <div className="flex flex-wrap gap-2">
                  {post.categories.map((category) => (
                    <Link key={category} href={withBasePath(`/categories/${encodeURIComponent(category.toLowerCase())}`)}>
                      <Badge
                        variant="default"
                        className="text-sm px-3 py-1 hover:bg-primary/90 transition-colors cursor-pointer"
                      >
                        {category}
                      </Badge>
                    </Link>
                  ))}
                </div>
              </div>
            )}

            {/* Title */}
            <h1 className="text-4xl md:text-5xl lg:text-6xl font-bold tracking-tight mb-6 leading-tight">
              {post.title}
            </h1>

            {/* Excerpt */}
            {post.excerpt && (
              <p className="text-xl text-muted-foreground mb-8 leading-relaxed max-w-3xl">{post.excerpt}</p>
            )}

            {/* Meta Information */}
            <div className="flex flex-wrap items-center gap-6 text-sm">
              {/* Author */}
              {post.owner && (
                <div className="flex items-center gap-3">
                  <Avatar className="w-10 h-10">
                    <AvatarImage src={post.owner.avatar_url || "/placeholder.svg"} alt={post.owner.name} />
                    <AvatarFallback>{post.owner.name.charAt(0).toUpperCase()}</AvatarFallback>
                  </Avatar>
                  <div>
                    <p className="font-medium">{post.owner.name}</p>
                    <p className="text-muted-foreground text-xs">Author</p>
                  </div>
                </div>
              )}

              <Separator orientation="vertical" className="h-12" />

              {/* Date */}
              <div className="flex items-center gap-2">
                <Calendar className="w-4 h-4 text-muted-foreground" />
                <div>
                  <time dateTime={post.createdAt} className="font-medium">
                    {format(new Date(post.createdAt), "MMMM d, yyyy")}
                  </time>
                  <p className="text-muted-foreground text-xs">Published</p>
                </div>
              </div>

              {/* Reading Time */}
              {post.content && (
                <>
                  <Separator orientation="vertical" className="h-12" />
                  <div className="flex items-center gap-2">
                    <Clock className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <p className="font-medium">{estimateReadingTime(post.content)} min read</p>
                      <p className="text-muted-foreground text-xs">Reading time</p>
                    </div>
                  </div>
                </>
              )}

              {/* Categories Count */}
              {post.categories && post.categories.length > 0 && (
                <>
                  <Separator orientation="vertical" className="h-12" />
                  <div className="flex items-center gap-2">
                    <Tag className="w-4 h-4 text-muted-foreground" />
                    <div>
                      <p className="font-medium">{post.categories.length} categories</p>
                      <p className="text-muted-foreground text-xs">Topics covered</p>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* Action Buttons */}
            <div className="flex flex-wrap items-center gap-4 mt-8">
              {post.notionUrl && <NotionLinkButton notionUrl={post.notionUrl} />}
              <ShareButtons title={post.title} slug={post.slug} />
            </div>
          </div>
        </div>
      </div>

      {/* Cover Image */}
      {post.coverImage && (
        <div className="container max-w-7xl mx-auto px-4 py-8">
          <div className="relative w-full h-[400px] md:h-[500px] lg:h-[600px] overflow-hidden rounded-xl shadow-2xl">
            <FallbackImage
              src={post.coverImage}
              alt={post.title}
              fill
              className="object-cover"
              priority
              fallbackSrc="/placeholder.svg?height=600&width=1200&text=Cover%20Image"
            />
          </div>
        </div>
      )}

      {/* Main Content */}
      <div className="container max-w-7xl mx-auto px-4 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-12">
          {/* Article Content */}
          <div className="lg:col-span-3">
            {/* Table of Contents - Mobile */}
            {post.content && (
              <div className="lg:hidden mb-8">
                <TableOfContents content={post.content} />
              </div>
            )}

            {/* Article Body */}
            <article className="prose prose-lg dark:prose-invert max-w-none">
              <div className="bg-card rounded-xl p-8 shadow-sm border">
                {post.content && <Mdx content={post.content} />}
              </div>
            </article>

            {/* Post Footer */}
            <div className="mt-12 space-y-8">
              {/* Categories - Detailed Section */}
              {post.categories && post.categories.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-lg">
                      <Folder className="w-5 h-5" />
                      Categories & Topics
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <p className="text-sm text-muted-foreground">
                        This article is categorized under the following topics. Click on any category to explore more
                        related content.
                      </p>
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                        {post.categories.map((category) => (
                          <Link key={category} href={withBasePath(`/categories/${encodeURIComponent(category.toLowerCase())}`)}>
                            <div className="flex items-center gap-3 p-3 rounded-lg border hover:bg-muted/50 transition-colors cursor-pointer group">
                              <div className="p-2 bg-primary/10 rounded-md group-hover:bg-primary/20 transition-colors">
                                <Tag className="w-4 h-4 text-primary" />
                              </div>
                              <div>
                                <p className="font-medium group-hover:text-primary transition-colors">{category}</p>
                                <p className="text-xs text-muted-foreground">
                                  {posts.filter((p) => p.categories?.includes(category)).length} posts
                                </p>
                              </div>
                            </div>
                          </Link>
                        ))}
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {/* Share Section */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Share2 className="w-5 h-5" />
                    Share this post
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <ShareButtons title={post.title} slug={post.slug} />
                </CardContent>
              </Card>

              {/* Post Navigation */}
              <PostNavigation currentSlug={post.slug} />
            </div>
          </div>

          {/* Sidebar */}
          <div className="lg:col-span-1">
            <div className="sticky top-8 space-y-6">
              {/* Table of Contents - Desktop */}
              {post.content && (
                <div className="hidden lg:block">
                  <TableOfContents content={post.content} />
                </div>
              )}

              {/* Categories Sidebar */}
              {post.categories && post.categories.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-lg">
                      <Folder className="w-5 h-5" />
                      Categories
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {post.categories.map((category) => (
                      <Link key={category} href={withBasePath(`/categories/${encodeURIComponent(category.toLowerCase())}`)}>
                        <div className="flex items-center justify-between p-2 rounded-lg hover:bg-muted/50 transition-colors cursor-pointer group">
                          <div className="flex items-center gap-2">
                            <Tag className="w-4 h-4 text-muted-foreground group-hover:text-primary transition-colors" />
                            <span className="font-medium group-hover:text-primary transition-colors">{category}</span>
                          </div>
                          <Badge variant="outline" className="text-xs">
                            {posts.filter((p) => p.categories?.includes(category)).length}
                          </Badge>
                        </div>
                      </Link>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Related Posts */}
              {relatedPosts.length > 0 && (
                <Card>
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2 text-lg">
                      <Tag className="w-5 h-5" />
                      Related Posts
                    </CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    {relatedPosts.map((relatedPost) => (
                      <div key={relatedPost.id} className="group">
                        <Link
                          href={`/posts/${relatedPost.slug}`}
                          className="block space-y-2 p-3 rounded-lg hover:bg-muted/50 transition-colors"
                        >
                          <h4 className="font-medium line-clamp-2 group-hover:text-primary transition-colors">
                            {relatedPost.title}
                          </h4>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Calendar className="w-3 h-3" />
                            {format(new Date(relatedPost.createdAt), "MMM d, yyyy")}
                          </div>
                          {relatedPost.categories && relatedPost.categories.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {relatedPost.categories.slice(0, 2).map((category) => (
                                <Badge key={category} variant="outline" className="text-xs">
                                  {category}
                                </Badge>
                              ))}
                            </div>
                          )}
                        </Link>
                      </div>
                    ))}
                  </CardContent>
                </Card>
              )}

              {/* Recent Posts */}
              <Card>
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-lg">
                    <Calendar className="w-5 h-5" />
                    Recent Posts
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  {posts.slice(0, 5).map((recentPost) => (
                    <div key={recentPost.id} className="group">
                      <Link
                        href={`/posts/${recentPost.slug}`}
                        className="block space-y-2 p-3 rounded-lg hover:bg-muted/50 transition-colors"
                      >
                        <h4 className="font-medium line-clamp-2 group-hover:text-primary transition-colors">
                          {recentPost.title}
                        </h4>
                        <div className="flex items-center gap-2 text-xs text-muted-foreground">
                          <Calendar className="w-3 h-3" />
                          {format(new Date(recentPost.createdAt), "MMM d, yyyy")}
                        </div>
                      </Link>
                    </div>
                  ))}
                </CardContent>
              </Card>
            </div>
          </div>
        </div>
      </div>
    </>
  )
}
