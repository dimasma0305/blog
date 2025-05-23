import { generateBlogMetadata, BlogStructuredData } from "@/components/seo"
import BlogPageClient from "@/components/blog-page-client"

export const metadata = generateBlogMetadata()

export default function BlogPage() {
  return (
    <>
      <BlogStructuredData />
      <BlogPageClient />
    </>
  )
}
