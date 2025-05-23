import fs from "fs"
import path from "path"
import matter from "gray-matter"
import { remark } from "remark"
import remarkGfm from "remark-gfm"
import rehypeSlug from "rehype-slug"
import rehypeAutolinkHeadings from "rehype-autolink-headings"
import remarkRehype from "remark-rehype"
import rehypeStringify from "rehype-stringify"
import rehypePrism from "rehype-prism-plus"

const postsDirectory = path.join(process.cwd(), "posts")

export type PostOwner = {
  id: string
  name: string
  avatar_url: string
  type: string
  person?: {
    email: string
  }
}

export type Post = {
  id: string
  slug: string
  title: string
  excerpt: string
  content: string
  createdAt: string
  updatedAt: string
  coverImage: string
  iconEmoji?: string
  categories: string[]
  verification: {
    state: string
    verified_by: string | null
    date: string | null
  }
  owner?: PostOwner
}

// Modify the processImagePaths function to be more robust
function processImagePaths(content: string, slug: string): string {
  // Debug the content to see what we're working with
  console.log(`Processing content for slug: ${slug}`)

  // First, handle the standard pattern with ./imgs/
  let processedContent = content.replace(
    /<img([^>]*)src="\.\/imgs\/([^"]*)"([^>]*)>/g,
    (match, before, imgPath, after) => {
      console.log(`Found image path: ./imgs/${imgPath}`)
      return `<img${before}src="/posts/${slug}/imgs/${imgPath}"${after} class="rounded-lg my-8" loading="lazy" onerror="this.onerror=null;this.src='/placeholder.svg?height=400&width=600&text=Image%20Not%20Found';">`
    },
  )

  // Then handle any remaining relative image paths that might not follow the exact ./imgs/ pattern
  processedContent = processedContent.replace(
    /<img([^>]*)src="(?!http|\/|data:)([^"]*)"([^>]*)>/g,
    (match, before, path, after) => {
      console.log(`Found relative image path: ${path}`)
      // If the path doesn't already start with /posts/${slug}/
      if (!path.startsWith(`/posts/${slug}/`)) {
        return `<img${before}src="/posts/${slug}/${path}"${after} class="rounded-lg my-8" loading="lazy" onerror="this.onerror=null;this.src='/placeholder.svg?height=400&width=600&text=Image%20Not%20Found';">`
      }
      return match
    },
  )

  // Handle absolute paths that might be missing
  processedContent = processedContent.replace(
    /<img([^>]*)src="\/posts\/([^"]*)"([^>]*)>/g,
    (match, before, path, after) => {
      console.log(`Found absolute image path: /posts/${path}`)
      return `<img${before}src="/posts/${path}"${after} class="rounded-lg my-8" loading="lazy" onerror="this.onerror=null;this.src='/placeholder.svg?height=400&width=600&text=Image%20Not%20Found';">`
    },
  )

  // Also handle markdown image syntax
  processedContent = processedContent.replace(/!\[(.*?)\]$$(\.\/imgs\/[^)]+)$$/g, (match, alt, path) => {
    const imgPath = path.replace("./imgs/", "")
    console.log(`Found markdown image path: ${path}`)
    return `![${alt}](/posts/${slug}/imgs/${imgPath})`
  })

  return processedContent
}

export async function getAllPosts(): Promise<Post[]> {
  // Check if posts directory exists
  if (!fs.existsSync(postsDirectory)) {
    console.log("Posts directory does not exist. Creating directory...")
    // Create the posts directory
    fs.mkdirSync(postsDirectory, { recursive: true })
    return []
  }

  // Get all folder names in the posts directory
  const folderNames = fs.readdirSync(postsDirectory)

  // If no posts are found, return an empty array
  if (folderNames.length === 0) {
    console.log("No posts found in the posts directory.")
    return []
  }

  const allPosts = await Promise.all(
    folderNames.map(async (folder) => {
      const readmePath = path.join(postsDirectory, folder, "README.md")

      // Skip if README.md doesn't exist
      if (!fs.existsSync(readmePath)) {
        console.log(`No README.md found in ${folder}`)
        return null
      }

      const post = await getPostBySlug(folder)
      return post
    }),
  )

  // Filter out null values and sort by date
  return allPosts
    .filter((post): post is Post => post !== null)
    .sort((a, b) => (new Date(b.createdAt) > new Date(a.createdAt) ? 1 : -1))
}

export async function getPostBySlug(slug: string): Promise<Post | null> {
  const readmePath = path.join(postsDirectory, slug, "README.md")

  // Return null if README.md doesn't exist
  if (!fs.existsSync(readmePath)) {
    console.log(`README.md does not exist for slug: ${slug}`)
    return null
  }

  // Read the README.md file
  const fileContents = fs.readFileSync(readmePath, "utf8")

  // Parse the frontmatter
  const { data, content } = matter(fileContents)

  // Process the markdown content with syntax highlighting
  const processedContent = await remark()
    .use(remarkGfm)
    .use(remarkRehype, { allowDangerousHtml: true })
    .use(rehypeSlug)
    .use(rehypeAutolinkHeadings)
    .use(rehypePrism, { showLineNumbers: true }) // Add syntax highlighting
    .use(rehypeStringify, { allowDangerousHtml: true })
    .process(content)

  const contentHtml = processedContent.toString()

  // Process image paths in the HTML content
  const processedHtml = processImagePaths(contentHtml, slug)

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
  const post: Post = {
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

  return post
}

export function getAllCategories(posts: Post[]): string[] {
  const categories = new Set<string>()

  posts.forEach((post) => {
    post.categories.forEach((category) => {
      categories.add(category)
    })
  })

  return Array.from(categories)
}

export function getPostsByCategory(posts: Post[], category: string): Post[] {
  return posts.filter((post) => post.categories.includes(category))
}
