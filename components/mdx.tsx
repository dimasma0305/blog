"use client"

import { useEffect, useRef } from "react"

interface MdxProps {
  content: string
}

export function Mdx({ content }: MdxProps) {
  const contentRef = useRef<HTMLDivElement>(null)

  // Add a useEffect to enhance images after rendering
  useEffect(() => {
    if (contentRef.current) {
      // Find all images in the content
      const images = contentRef.current.querySelectorAll("img")

      // Add fallback for each image
      images.forEach((img) => {
        // Add error handler if not already present
        if (!img.hasAttribute("onerror")) {
          img.onerror = function () {
            console.error(`Failed to load image: ${(this as HTMLImageElement).src}`)
            // @ts-ignore - we know this is an HTMLImageElement
            this.onerror = null
            // @ts-ignore - we know this is an HTMLImageElement
            this.src = "/placeholder.svg?height=400&width=600&text=Image%20Not%20Found"
          }
        }

        // Add loading lazy if not already present
        if (!img.hasAttribute("loading")) {
          img.setAttribute("loading", "lazy")
        }

        // Add class for styling if not already present
        if (!img.classList.contains("rounded-lg")) {
          img.classList.add("rounded-lg", "my-8")
        }
      })

      // Add syntax highlighting to code blocks
      const codeBlocks = contentRef.current.querySelectorAll("pre code")
      if (codeBlocks.length > 0 && typeof window !== "undefined") {
        import("prismjs")
          .then((Prism) => {
            codeBlocks.forEach((block) => {
              if (block.className.includes("language-")) {
                Prism.highlightElement(block)
              }
            })
          })
          .catch((err) => {
            console.error("Failed to load syntax highlighting:", err)
          })
      }
    }
  }, [content])

  return (
    <div
      ref={contentRef}
      className="mdx prose dark:prose-invert max-w-none"
      dangerouslySetInnerHTML={{ __html: content }}
    />
  )
}
