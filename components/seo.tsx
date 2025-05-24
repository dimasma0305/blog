import { Metadata } from "next"
import type { Post } from "@/lib/posts-client"

interface SEOProps {
  post: Post
  baseUrl?: string
}

export function generatePostMetadata({ post, baseUrl = "https://dimasma0305.github.io/blog" }: SEOProps): Metadata {
  const postUrl = `${baseUrl}/posts/${post.slug}`
  const imageUrl = post.coverImage?.startsWith('http') 
    ? post.coverImage 
    : `${baseUrl}${post.coverImage || '/og-image.jpg'}`

  // Create a clean description from excerpt
  const description = post.excerpt
    .replace(/[#*_`]/g, '')
    .replace(/\[([^\]]+)\]\([^)]+\)/g, '$1')
    .trim()
    .substring(0, 160)

  // Generate keywords from categories and title
  const keywords = [
    ...post.categories,
    'cybersecurity',
    'CTF',
    'writeup',
    'security research',
    'Dimas Maulana'
  ].join(', ')

  return {
    title: post.title,
    description,
    keywords,
    authors: [{ name: post.owner?.name || 'Dimas Maulana' }],
    creator: post.owner?.name || 'Dimas Maulana',
    publisher: 'Dimas Maulana',
    formatDetection: {
      email: false,
      address: false,
      telephone: false,
    },
    metadataBase: new URL(baseUrl),
    alternates: {
      canonical: postUrl,
    },
    openGraph: {
      type: 'article',
      url: postUrl,
      title: post.title,
      description,
      siteName: 'Dimas Maulana Blog',
      publishedTime: post.createdAt,
      modifiedTime: post.updatedAt,
      authors: [post.owner?.name || 'Dimas Maulana'],
      tags: [...post.categories],
      images: [
        {
          url: imageUrl,
          width: 1200,
          height: 630,
          alt: post.title,
        },
      ],
    },
    twitter: {
      card: 'summary_large_image',
      title: post.title,
      description,
      creator: '@dimasma__',
      images: [imageUrl],
    },
    robots: {
      index: true,
      follow: true,
      googleBot: {
        index: true,
        follow: true,
        'max-video-preview': -1,
        'max-image-preview': 'large',
        'max-snippet': -1,
      },
    },
    other: {
      'article:author': post.owner?.name || 'Dimas Maulana',
      'article:published_time': post.createdAt,
      'article:modified_time': post.updatedAt,
      'article:section': post.categories[0] || 'Technology',
      'article:tag': post.categories.join(','),
    },
  }
}

export function generateBlogMetadata(baseUrl = "https://dimasma0305.github.io/blog"): Metadata {
  return {
    title: "Blog | Cybersecurity Research & CTF Writeups",
    description: "Explore cybersecurity research, CTF writeups, vulnerability analysis, and security tutorials by Dimas Maulana. Learn about web security, penetration testing, and ethical hacking.",
    keywords: "cybersecurity blog, CTF writeups, security research, penetration testing, web security, vulnerability analysis, ethical hacking, bug bounty, infosec",
    alternates: {
      canonical: `${baseUrl}/blog`,
    },
    openGraph: {
      type: 'website',
      url: `${baseUrl}/blog`,
      title: "Blog | Cybersecurity Research & CTF Writeups",
      description: "Explore cybersecurity research, CTF writeups, vulnerability analysis, and security tutorials by Dimas Maulana.",
      siteName: 'Dimas Maulana Blog',
      images: [
        {
          url: `${baseUrl}/og-image.jpg`,
          width: 1200,
          height: 630,
          alt: "Dimas Maulana Blog",
        },
      ],
    },
    twitter: {
      card: 'summary_large_image',
      title: "Blog | Cybersecurity Research & CTF Writeups",
      description: "Explore cybersecurity research, CTF writeups, vulnerability analysis, and security tutorials.",
      creator: '@dimasma__',
      images: [`${baseUrl}/og-image.jpg`],
    },
  }
}

// JSON-LD Structured Data Component
export function PostStructuredData({ post, baseUrl = "https://dimasma0305.github.io/blog" }: SEOProps) {
  const postUrl = `${baseUrl}/posts/${post.slug}`
  const imageUrl = post.coverImage?.startsWith('http') 
    ? post.coverImage 
    : `${baseUrl}${post.coverImage || '/og-image.jpg'}`

  const structuredData = {
    "@context": "https://schema.org",
    "@type": "BlogPosting",
    headline: post.title,
    description: post.excerpt.replace(/[#*_`]/g, '').replace(/\[([^\]]+)\]\([^)]+\)/g, '$1').trim(),
    image: imageUrl,
    url: postUrl,
    datePublished: post.createdAt,
    dateModified: post.updatedAt,
    author: {
      "@type": "Person",
      name: post.owner?.name || "Dimas Maulana",
      url: baseUrl,
      sameAs: [
        "https://twitter.com/dimasma__",
        "https://github.com/dimasma0305",
        "https://linkedin.com/in/dimas-maulana"
      ]
    },
    publisher: {
      "@type": "Organization",
      name: "Dimas Maulana",
      url: baseUrl,
      logo: {
        "@type": "ImageObject",
        url: `${baseUrl}/logo.png`
      }
    },
    mainEntityOfPage: {
      "@type": "WebPage",
      "@id": postUrl
    },
    keywords: post.categories.join(", "),
    wordCount: post.wordCount || 0,
    articleSection: post.categories[0] || "Technology",
    inLanguage: "en-US",
    potentialAction: {
      "@type": "ReadAction",
      target: postUrl
    }
  }

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
    />
  )
}

// Blog Section Structured Data
export function BlogStructuredData({ baseUrl = "https://dimasma0305.github.io/blog" }) {
  const structuredData = {
    "@context": "https://schema.org",
    "@type": "Blog",
    url: `${baseUrl}/blog`,
    name: "Dimas Maulana Blog",
    description: "Cybersecurity research, CTF writeups, vulnerability analysis, and security tutorials",
    publisher: {
      "@type": "Person",
      name: "Dimas Maulana",
      url: baseUrl,
      sameAs: [
        "https://twitter.com/dimasma__",
        "https://github.com/dimasma0305",
        "https://linkedin.com/in/dimas-maulana"
      ]
    },
    inLanguage: "en-US",
    potentialAction: {
      "@type": "ReadAction",
      target: `${baseUrl}/blog`
    }
  }

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(structuredData) }}
    />
  )
}
