"use client"

import { useState, useMemo } from "react"
import Link from "next/link"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import type { Post } from "@/lib/posts-client"

interface CategoriesProps {
  posts: Post[]
}

export function Categories({ posts }: CategoriesProps) {
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)

  // Extract categories from posts with counts
  const categories = useMemo(() => {
    const categoryMap = new Map<string, number>()

    posts.forEach((post) => {
      if (post.categories && Array.isArray(post.categories)) {
        post.categories.forEach((category) => {
          if (category && typeof category === "string") {
            categoryMap.set(category, (categoryMap.get(category) || 0) + 1)
          }
        })
      }
    })

    // Convert to array and sort by count (most popular first)
    return Array.from(categoryMap.entries())
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
  }, [posts])

  return (
    <Card>
      <CardHeader>
        <CardTitle>Categories ({categories.length})</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {categories.length > 0 ? (
            categories.map(({ name, count }) => (
              <div key={name}>
                <Link href={`/categories/${encodeURIComponent(name)}`}>
                  <Badge
                    variant={selectedCategory === name ? "default" : "secondary"}
                    className="cursor-pointer flex items-center gap-1 hover:bg-primary hover:text-primary-foreground transition-colors"
                    onClick={() => setSelectedCategory(name)}
                  >
                    {name}
                    <span className="text-xs opacity-70">({count})</span>
                  </Badge>
                </Link>
              </div>
            ))
          ) : (
            <div className="text-center py-4">
              <p className="text-sm text-muted-foreground">No categories found</p>
              <p className="text-xs text-muted-foreground mt-1">Posts loaded: {posts.length}</p>
            </div>
          )}
        </div>

        {categories.length > 0 && (
          <div className="mt-6">
            <h3 className="mb-3 text-sm font-medium text-muted-foreground">Popular Topics</h3>
            <div className="flex flex-wrap gap-2">
              {categories.slice(0, 5).map(({ name }) => (
                <Link key={name} href={`/categories/${encodeURIComponent(name)}`}>
                  <Badge variant="outline" className="hover:bg-muted transition-colors">
                    {name}
                  </Badge>
                </Link>
              ))}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
