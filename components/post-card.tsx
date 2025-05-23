"use client"

import { useState } from "react"
import Link from "next/link"
import { format } from "date-fns"
import { motion } from "framer-motion"
import { Calendar } from "lucide-react"

import type { Post } from "@/lib/posts-client"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardFooter, CardHeader } from "@/components/ui/card"
import { FallbackImage } from "@/components/fallback-image"
import { NotionLinkButton } from "@/components/notion-link-button"

interface PostCardProps {
  post: Post
}

export default function PostCard({ post }: PostCardProps) {
  const [isHovered, setIsHovered] = useState(false)

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      whileHover={{ y: -5 }}
      onHoverStart={() => setIsHovered(true)}
      onHoverEnd={() => setIsHovered(false)}
    >
      <Link href={`/posts/${post.slug}`}>
        <Card className="overflow-hidden h-full transition-shadow hover:shadow-lg">
          {post.coverImage && (
            <div className="relative w-full h-48 overflow-hidden">
              <motion.div
                animate={{ scale: isHovered ? 1.05 : 1 }}
                transition={{ duration: 0.3 }}
                className="w-full h-full"
              >
                <FallbackImage
                  src={post.coverImage}
                  alt={post.title}
                  fill
                  className="object-cover"
                  fallbackSrc="/placeholder.svg?height=192&width=384"
                />
              </motion.div>
              {post.iconEmoji && (
                <div className="absolute flex items-center justify-center w-10 h-10 text-xl bg-white rounded-full dark:bg-gray-800 top-4 right-4">
                  {post.iconEmoji}
                </div>
              )}
              {post.notionUrl && (
                <div 
                  className="absolute top-4 left-4"
                  onClick={(e) => e.preventDefault()}
                >
                  <NotionLinkButton 
                    notionUrl={post.notionUrl} 
                    variant="badge"
                  />
                </div>
              )}
            </div>
          )}
          <CardHeader className="pb-2">
            <h3 className="text-xl font-bold line-clamp-2">{post.title}</h3>
          </CardHeader>
          <CardContent>
            <p className="text-muted-foreground line-clamp-3">{post.excerpt}</p>
          </CardContent>
          <CardFooter className="flex flex-wrap items-center justify-between">
            <div className="flex items-center text-sm text-muted-foreground">
              <Calendar className="w-4 h-4 mr-1" />
              <time dateTime={post.createdAt}>{format(new Date(post.createdAt), "MMM d, yyyy")}</time>
            </div>
            <div className="flex gap-2 mt-2">
              {post.categories && post.categories.length > 0 && (
                <Badge variant="secondary">
                  {post.categories[0]}
                </Badge>
              )}
            </div>
          </CardFooter>
        </Card>
      </Link>
    </motion.div>
  )
}
