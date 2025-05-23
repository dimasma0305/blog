"use client"

import { useEffect, useState } from "react"
import { useParams } from "next/navigation"
import { format } from "date-fns"
import { ArrowLeft, Calendar, User } from "lucide-react"
import Link from "next/link"

import { fetchPostBySlug } from "@/lib/posts-loader"
import type { Post } from "@/lib/posts-client"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Mdx } from "@/components/mdx"
import { PostNavigation } from "@/components/post-navigation"
import { ShareButtons } from "@/components/share-buttons"
import { FallbackImage } from "@/components/fallback-image"
import { LoadingSpinner } from "@/components/loading-spinner"
import { NotionLinkButton } from "@/components/notion-link-button"
import { PostStructuredData } from "@/components/seo"

interface PostPageClientProps {
  slug: string
}

export default function PostPageClient({ slug }: PostPageClientProps) {
  const [post, setPost] = useState<Post | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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
      <div className="container max-w-4xl px-4 py-12 mx-auto">
        <div className="flex items-center justify-center py-12">
          <LoadingSpinner />
        </div>
      </div>
    )
  }

  if (error || !post) {
    return (
      <div className="container max-w-4xl px-4 py-12 mx-auto">
        <div className="text-center py-12">
          <h1 className="text-2xl font-bold mb-4">Post Not Found</h1>
          <p className="text-muted-foreground mb-4">{error || "The requested post could not be found."}</p>
          <Link href="/blog">
            <Button>
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Blog
            </Button>
          </Link>
        </div>
      </div>
    )
  }

  return (
    <>
      <PostStructuredData post={post} />
      <div className="container max-w-4xl px-4 py-12 mx-auto">
        <div className="mb-8">
          <Link href="/blog">
            <Button variant="ghost" className="pl-0 mb-4">
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to all posts
            </Button>
          </Link>

          {post.coverImage && (
            <div className="relative w-full mb-8 overflow-hidden rounded-lg aspect-video">
              <FallbackImage
                src={post.coverImage}
                alt={post.title}
                fill
                className="object-cover"
                priority
                fallbackSrc="/placeholder.svg?height=600&width=1200&text=Cover%20Image"
              />
            </div>
          )}

          <h1 className="mb-4 text-4xl font-bold tracking-tight md:text-5xl">{post.title}</h1>

          <div className="flex flex-wrap items-center gap-4 mb-8 text-sm text-muted-foreground">
            <div className="flex items-center gap-1">
              <Calendar className="w-4 h-4" />
              <time dateTime={post.createdAt}>{format(new Date(post.createdAt), "MMMM d, yyyy")}</time>
            </div>

            {post.owner && (
              <div className="flex items-center gap-2">
                <User className="w-4 h-4" />
                <div className="flex items-center gap-2">
                  {post.owner.avatar_url && (
                    <div className="relative w-6 h-6 overflow-hidden rounded-full">
                      <FallbackImage
                        src={post.owner.avatar_url}
                        alt={post.owner.name}
                        fill
                        className="object-cover"
                        fallbackSrc="https://avatars.githubusercontent.com/u/92920739"
                      />
                    </div>
                  )}
                  <span>{post.owner.name}</span>
                </div>
              </div>
            )}

            {post.categories && post.categories.length > 0 && (
              <div className="flex flex-wrap gap-2">
                {post.categories.map((category) => (
                  <Badge key={category} variant="secondary">
                    {category}
                  </Badge>
                ))}
              </div>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-4 mb-8">
            {post.notionUrl && (
              <NotionLinkButton notionUrl={post.notionUrl} />
            )}
            <ShareButtons title={post.title} slug={post.slug} />
          </div>
        </div>

        <article className="prose dark:prose-invert max-w-none">
          <Mdx content={post.content} />
        </article>

        <PostNavigation currentSlug={post.slug} />
      </div>
    </>
  )
} 