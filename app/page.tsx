"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { fetchAllPosts } from "@/lib/posts-loader"
import type { Post } from "@/lib/posts-client"
import PostCard from "@/components/post-card"
import { HeroSection } from "@/components/hero-section"
import { ProjectsSection } from "@/components/projects-section"
import { SkillsSection } from "@/components/skills-section"
import { CTFSection } from "@/components/ctf-section"
import { ExperienceSection } from "@/components/experience-section"
import { FallbackImage } from "@/components/fallback-image"
import { LoadingSpinner } from "@/components/loading-spinner"

export default function Home() {
  const [posts, setPosts] = useState<Post[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const loadPosts = async () => {
      try {
        const allPosts = await fetchAllPosts()
        setPosts(allPosts)
      } catch (error) {
        console.error("Error loading posts:", error)
      } finally {
        setLoading(false)
      }
    }

    loadPosts()
  }, [])

  return (
    <div className="min-h-screen">
      <HeroSection />

      <div className="container px-4 py-16 mx-auto max-w-7xl" id="about">
        <h2 className="mb-8 text-3xl font-bold tracking-tight">About Me</h2>
        <div className="grid gap-8 md:grid-cols-2">
          <div className="space-y-4">
            <p className="text-lg">
              I'm a cybersecurity enthusiast and CTF player based in Denpasar, Bali, Indonesia. Currently exploring
              cyber security and computer science with a focus on Linux OS and security.
            </p>
            <p className="text-lg">
              I'm a member of{" "}
              <Link href="https://github.com/TCP1P" className="text-primary hover:underline">
                @TCP1P
              </Link>{" "}
              and
              <Link href="https://github.com/project-sekai-ctf" className="text-primary hover:underline">
                {" "}
                @project-sekai-ctf
              </Link>{" "}
              teams, where I participate in various CTF competitions and security research.
            </p>
            <p className="text-lg">
              I enjoy creating CTF challenges, developing security tools, and sharing my knowledge through blog posts
              and resources.
            </p>
          </div>
          <div className="flex items-center justify-center">
            <div className="relative w-64 h-64 overflow-hidden rounded-full border-4 border-primary/20">
              <FallbackImage
                src="/placeholder.svg?height=256&width=256"
                alt="Dimas Maulana"
                fill
                className="object-cover"
              />
            </div>
          </div>
        </div>
      </div>

      <SkillsSection />
      <ExperienceSection />
      <ProjectsSection />
      <CTFSection />

      <div className="container px-4 py-16 mx-auto max-w-7xl" id="blog">
        <div className="flex items-center justify-between mb-8">
          <h2 className="text-3xl font-bold tracking-tight">Latest Blog Posts</h2>
          <Link href="/blog" className="text-primary hover:underline">
            View all posts →
          </Link>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-12">
            <LoadingSpinner />
          </div>
        ) : posts.length > 0 ? (
          <div className="grid gap-8 sm:grid-cols-2 lg:grid-cols-3">
            {posts.slice(0, 3).map((post) => (
              <PostCard key={post.id} post={post} />
            ))}
          </div>
        ) : (
          <div className="text-center py-12">
            <p className="text-muted-foreground">No posts found. Add markdown files to the /posts directory.</p>
          </div>
        )}
      </div>
    </div>
  )
}
