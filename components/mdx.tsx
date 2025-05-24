"use client"

import { useEffect, useRef } from "react"

interface MdxProps {
  content: string
}

export function Mdx({ content }: MdxProps) {
  const contentRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (contentRef.current) {
      // Enhanced image handling
      const images = contentRef.current.querySelectorAll("img")
      images.forEach((img) => {
        if (!img.hasAttribute("onerror")) {
          img.onerror = function () {
            // @ts-ignore
            this.onerror = null
            // @ts-ignore
            this.src = "/placeholder.svg?height=400&width=600&text=Image%20Not%20Found"
          }
        }

        if (!img.hasAttribute("loading")) {
          img.setAttribute("loading", "lazy")
        }

        // Enhanced image styling
        if (!img.classList.contains("enhanced")) {
          img.classList.add(
            "enhanced",
            "rounded-xl",
            "shadow-lg",
            "my-8",
            "border",
            "transition-transform",
            "hover:scale-[1.02]",
            "cursor-zoom-in",
          )
        }
      })

      // Enhanced heading styling and ID generation
      const headings = contentRef.current.querySelectorAll("h1, h2, h3, h4, h5, h6")
      headings.forEach((heading, index) => {
        if (!heading.id) {
          const text = heading.textContent || ""
          const slug = text
            .toLowerCase()
            .replace(/[^\w\s-]/g, "")
            .replace(/\s+/g, "-")
            .trim()

          heading.id = slug || `heading-${index}`
        }

        // Enhanced heading styling
        heading.style.scrollMarginTop = "120px"
        heading.classList.add("group", "relative")

        // Add anchor link
        if (!heading.querySelector(".anchor-link")) {
          const anchor = document.createElement("a")
          anchor.href = `#${heading.id}`
          anchor.className =
            "anchor-link absolute -left-6 top-0 opacity-0 group-hover:opacity-100 transition-opacity text-muted-foreground hover:text-primary"
          anchor.innerHTML = "#"
          anchor.setAttribute("aria-label", "Link to this section")
          heading.appendChild(anchor)
        }
      })

      // Enhanced code block styling
      const codeBlocks = contentRef.current.querySelectorAll("pre")
      codeBlocks.forEach((pre) => {
        if (!pre.classList.contains("enhanced")) {
          pre.classList.add(
            "enhanced",
            "relative",
            "rounded-xl",
            "border",
            "shadow-sm",
            "bg-muted/50",
            "my-6",
            "overflow-hidden",
          )

          // Add language label if available
          const code = pre.querySelector("code")
          if (code) {
            const className = code.className
            const languageMatch = className.match(/language-(\w+)/)

            if (languageMatch && !pre.querySelector(".language-label")) {
              const language = languageMatch[1]
              const label = document.createElement("div")
              label.className =
                "language-label absolute top-2 right-2 px-2 py-1 text-xs bg-background/80 backdrop-blur-sm rounded border text-muted-foreground"
              label.textContent = language.toUpperCase()
              pre.appendChild(label)
            }
          }

          // Enhanced copy button
          if (!pre.querySelector(".copy-button")) {
            const copyButton = document.createElement("button")
            copyButton.className =
              "copy-button absolute top-2 left-2 px-3 py-1 text-xs bg-background/80 backdrop-blur-sm border rounded hover:bg-muted transition-colors"
            copyButton.textContent = "Copy"
            copyButton.onclick = () => {
              const code = pre.querySelector("code")?.textContent || ""
              navigator.clipboard.writeText(code).then(() => {
                copyButton.textContent = "Copied!"
                copyButton.classList.add("text-green-600")
                setTimeout(() => {
                  copyButton.textContent = "Copy"
                  copyButton.classList.remove("text-green-600")
                }, 2000)
              })
            }
            pre.appendChild(copyButton)
          }
        }
      })

      // Enhanced blockquote styling
      const blockquotes = contentRef.current.querySelectorAll("blockquote")
      blockquotes.forEach((blockquote) => {
        if (!blockquote.classList.contains("enhanced")) {
          blockquote.classList.add("enhanced", "border-l-4", "border-primary", "bg-muted/30", "rounded-r-lg", "my-6")
        }
      })

      // Enhanced table styling
      const tables = contentRef.current.querySelectorAll("table")
      tables.forEach((table) => {
        if (!table.classList.contains("enhanced")) {
          table.classList.add("enhanced")

          // Wrap table in a container for better responsive handling
          if (!table.parentElement?.classList.contains("table-container")) {
            const wrapper = document.createElement("div")
            wrapper.className = "table-container overflow-x-auto rounded-lg border my-6"
            table.parentNode?.insertBefore(wrapper, table)
            wrapper.appendChild(table)
          }
        }
      })
    }
  }, [content])

  return (
    <div
      ref={contentRef}
      className="mdx prose prose-lg dark:prose-invert max-w-none 
        prose-headings:scroll-mt-24
        prose-a:text-primary prose-a:no-underline hover:prose-a:underline
        prose-code:bg-muted prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-sm
        prose-pre:bg-transparent prose-pre:p-0
        prose-img:rounded-xl prose-img:shadow-lg
        prose-blockquote:border-l-primary prose-blockquote:bg-muted/30
        prose-th:bg-muted prose-th:font-semibold
        prose-td:border-border prose-th:border-border"
      dangerouslySetInnerHTML={{ __html: content }}
    />
  )
}
