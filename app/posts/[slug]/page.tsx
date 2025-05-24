import PostPageClient from "@/components/post-page-client"
import { generatePostMetadata } from "@/components/seo"
import type { Metadata } from "next"

// Generate static params for all posts
export async function generateStaticParams() {
  try {
    // Read the blog-index.json file directly from the file system during build
    const fs = require("fs")
    const path = require("path")

    const indexPath = path.join(process.cwd(), "public", "blog-index.json")
    const indexContent = fs.readFileSync(indexPath, "utf8")
    const blogIndex = JSON.parse(indexContent)

    // Extract slugs from the blog-index.json format
    const slugs = blogIndex.posts?.published?.map((post: any) => post.slug) || []

    console.log(`📝 Generated static params for ${slugs.length} posts from blog-index.json`)

    return slugs.map((slug: string) => ({
      slug: slug,
    }))
  } catch (error) {
    console.error("Error generating static params:", error)
    console.log("🔄 Attempting to generate blog-index.json...")

    // Try to generate the blog index if it doesn't exist
    try {
      const { generateBlogIndex } = require("../../../scripts/generate-blog-index")
      await generateBlogIndex()

      // Try again after generating
      const fs = require("fs")
      const path = require("path")
      const indexPath = path.join(process.cwd(), "public", "blog-index.json")
      const indexContent = fs.readFileSync(indexPath, "utf8")
      const blogIndex = JSON.parse(indexContent)

      const slugs = blogIndex.posts?.published?.map((post: any) => post.slug) || []
      console.log(`✅ Generated blog-index and static params for ${slugs.length} posts`)

      return slugs.map((slug: string) => ({
        slug: slug,
      }))
    } catch (generateError) {
      console.error("Failed to generate blog-index:", generateError)
      return []
    }
  }
}

// Generate metadata for each post
export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  try {
    const { slug } = await params

    // Read the post data from the blog-index for metadata generation
    const fs = require("fs")
    const path = require("path")

    const indexPath = path.join(process.cwd(), "public", "blog-index.json")
    const indexContent = fs.readFileSync(indexPath, "utf8")
    const blogIndex = JSON.parse(indexContent)

    // Find the post in the blog index
    const post = blogIndex.posts?.published?.find((p: any) => p.slug === slug)

    if (!post) {
      // Fallback metadata for posts not found in index
      return {
        title: "Post Not Found",
        description: "The requested blog post could not be found.",
      }
    }

    // Generate SEO metadata for the post
    return generatePostMetadata({
      post: {
        id: post.id,
        slug: post.slug,
        title: post.title,
        excerpt: post.excerpt || "",
        createdAt: post.created_time,
        updatedAt: post.last_edited_time,
        coverImage: post.featured_image || "",
        iconEmoji: "",
        categories: post.properties?.tags || [],
        verification: {
          state: "unverified",
          verified_by: null,
          date: null,
        },
      },
    })
  } catch (error) {
    console.error("Error generating metadata:", error)
    return {
      title: "Blog Post",
      description: "A blog post by Dimas Maulana",
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
