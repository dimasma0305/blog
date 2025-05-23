"use client"

import { useState } from "react"
import Link from "next/link"
import { motion } from "framer-motion"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { getAllCategories } from "@/lib/posts-client" // Import from client-safe file
import type { Post } from "@/lib/posts-client"

interface CategoriesProps {
  posts: Post[]
}

export function Categories({ posts }: CategoriesProps) {
  const [selectedCategory, setSelectedCategory] = useState<string | null>(null)
  const categories = getAllCategories(posts)

  return (
    <Card>
      <CardHeader>
        <CardTitle>Categories</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex flex-wrap gap-2">
          {categories.length > 0 ? (
            categories.map((category) => (
              <motion.div key={category} whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }}>
                <Link href={`/categories/${category}`}>
                  <Badge
                    variant={selectedCategory === category ? "default" : "secondary"}
                    className="cursor-pointer"
                    onClick={() => setSelectedCategory(category)}
                  >
                    {category}
                  </Badge>
                </Link>
              </motion.div>
            ))
          ) : (
            <p className="text-sm text-muted-foreground">No categories found</p>
          )}
        </div>

        <div className="mt-8">
          <h3 className="mb-4 text-lg font-medium">Popular Tags</h3>
          <div className="flex flex-wrap gap-2">
            <Badge variant="outline">CTF</Badge>
            <Badge variant="outline">Security</Badge>
            <Badge variant="outline">Programming</Badge>
            <Badge variant="outline">Web</Badge>
            <Badge variant="outline">Hacking</Badge>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
