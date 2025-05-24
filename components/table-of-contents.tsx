"use client"

import { useEffect, useState, useRef, useCallback } from "react"
import { ChevronRight, ChevronDown, BookOpen, Maximize2, Minimize2, Eye, EyeOff } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible"
import { Badge } from "@/components/ui/badge"

interface TocItem {
  id: string
  title: string
  level: number
  children: TocItem[]
}

interface TableOfContentsProps {
  content: string
}

export function TableOfContents({ content }: TableOfContentsProps) {
  const [tocItems, setTocItems] = useState<TocItem[]>([])
  const [activeId, setActiveId] = useState<string>("")
  const [isOpen, setIsOpen] = useState(false)
  const [isFloating, setIsFloating] = useState(false)
  const [isExpanded, setIsExpanded] = useState(false)
  const [collapsedSections, setCollapsedSections] = useState<Set<string>>(new Set())
  const [showOnlyTopLevel, setShowOnlyTopLevel] = useState(false)
  const [dynamicHeight, setDynamicHeight] = useState("60vh")
  const [isScrolling, setIsScrolling] = useState(false)
  const observerRef = useRef<IntersectionObserver | null>(null)
  const tocRef = useRef<HTMLDivElement>(null)
  const scrollTimeoutRef = useRef<NodeJS.Timeout>()

  // Calculate dynamic height based on viewport and content
  const calculateDynamicHeight = useCallback(() => {
    const viewportHeight = window.innerHeight
    const headerHeight = 100
    const footerHeight = 100
    const padding = 40

    const availableHeight = viewportHeight - headerHeight - footerHeight - padding
    const maxHeight = Math.max(300, Math.min(availableHeight, viewportHeight * 0.8))

    setDynamicHeight(`${maxHeight}px`)
  }, [])

  useEffect(() => {
    calculateDynamicHeight()
    window.addEventListener("resize", calculateDynamicHeight)
    return () => window.removeEventListener("resize", calculateDynamicHeight)
  }, [calculateDynamicHeight])

  // Parse content and extract headings
  useEffect(() => {
    if (!content) return

    const tempDiv = document.createElement("div")
    tempDiv.innerHTML = content

    const headings = tempDiv.querySelectorAll("h1, h2, h3, h4, h5, h6")
    const items: TocItem[] = []
    const stack: TocItem[] = []

    headings.forEach((heading, index) => {
      const level = Number.parseInt(heading.tagName.charAt(1))
      const title = heading.textContent?.trim() || ""
      const id = `heading-${index}`

      if (heading.id === "") {
        heading.id = id
      }

      const item: TocItem = {
        id: heading.id || id,
        title,
        level,
        children: [],
      }

      while (stack.length > 0 && stack[stack.length - 1].level >= level) {
        stack.pop()
      }

      if (stack.length === 0) {
        items.push(item)
      } else {
        stack[stack.length - 1].children.push(item)
      }

      stack.push(item)
    })

    setTocItems(items)

    // Auto-enable smart features for long TOCs
    const totalItems = items.reduce((count, item) => {
      return count + 1 + item.children.length
    }, 0)

    if (totalItems > 15) {
      setShowOnlyTopLevel(true)
    }

    if (totalItems > 25) {
      setIsFloating(true)
    }

    const contentElement = document.querySelector(".mdx")
    if (contentElement) {
      const actualHeadings = contentElement.querySelectorAll("h1, h2, h3, h4, h5, h6")
      actualHeadings.forEach((heading, index) => {
        if (!heading.id) {
          heading.id = `heading-${index}`
        }
      })
    }
  }, [content])

  // Set up intersection observer
  useEffect(() => {
    if (tocItems.length === 0) return

    const headingElements = tocItems.flatMap(function flattenItems(item: TocItem): string[] {
      return [item.id, ...item.children.flatMap(flattenItems)]
    })

    observerRef.current = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            setActiveId(entry.target.id)
          }
        })
      },
      {
        rootMargin: "-20% 0% -35% 0%",
        threshold: 0,
      },
    )

    headingElements.forEach((id) => {
      const element = document.getElementById(id)
      if (element) {
        observerRef.current?.observe(element)
      }
    })

    return () => {
      observerRef.current?.disconnect()
    }
  }, [tocItems])

  const scrollToHeading = (id: string) => {
    const element = document.getElementById(id)
    if (element) {
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
      })
    }
  }

  const toggleSection = (itemId: string) => {
    setCollapsedSections((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(itemId)) {
        newSet.delete(itemId)
      } else {
        newSet.add(itemId)
      }
      return newSet
    })
  }

  const handleScroll = () => {
    setIsScrolling(true)
    if (scrollTimeoutRef.current) {
      clearTimeout(scrollTimeoutRef.current)
    }
    scrollTimeoutRef.current = setTimeout(() => {
      setIsScrolling(false)
    }, 1000)
  }

  const renderTocItems = (items: TocItem[], depth = 0) => {
    return items.map((item) => {
      const hasChildren = item.children.length > 0
      const isCollapsed = collapsedSections.has(item.id)
      const shouldShowChildren = !showOnlyTopLevel || depth === 0 || !isCollapsed

      return (
        <div key={item.id} className={`${depth > 0 ? "ml-4 border-l border-border pl-4" : ""}`}>
          <div className="flex items-center gap-1">
            {hasChildren && (
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => toggleSection(item.id)}>
                {isCollapsed ? <ChevronRight className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
              </Button>
            )}
            <button
              onClick={() => scrollToHeading(item.id)}
              className={`
                flex-1 text-left px-3 py-2 rounded-md text-sm transition-all duration-200
                hover:bg-muted hover:text-foreground
                ${
                  activeId === item.id
                    ? "bg-primary/10 text-primary font-medium border-l-2 border-primary"
                    : "text-muted-foreground hover:text-foreground"
                }
                ${depth === 0 ? "font-medium" : ""}
                ${hasChildren ? "ml-0" : "ml-7"}
              `}
            >
              <span className="line-clamp-2 leading-relaxed">{item.title}</span>
            </button>
          </div>
          {hasChildren && shouldShowChildren && !isCollapsed && (
            <div className="mt-1 space-y-1">{renderTocItems(item.children, depth + 1)}</div>
          )}
        </div>
      )
    })
  }

  const getTotalItemCount = () => {
    return tocItems.reduce((count, item) => {
      return count + 1 + item.children.length
    }, 0)
  }

  if (tocItems.length === 0) {
    return null
  }

  const totalItems = getTotalItemCount()

  return (
    <>
      {/* Mobile Toggle */}
      <div className="lg:hidden">
        <Collapsible open={isOpen} onOpenChange={setIsOpen}>
          <CollapsibleTrigger asChild>
            <Button variant="outline" className="w-full justify-between h-12">
              <div className="flex items-center gap-3">
                <BookOpen className="w-5 h-5" />
                <span className="font-medium">Table of Contents</span>
                <Badge variant="secondary" className="text-xs">
                  {totalItems}
                </Badge>
              </div>
              {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
            </Button>
          </CollapsibleTrigger>
          <CollapsibleContent className="mt-4">
            <Card>
              <CardHeader className="pb-2">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-sm">Navigation</CardTitle>
                  <div className="flex gap-1">
                    {totalItems > 10 && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => setShowOnlyTopLevel(!showOnlyTopLevel)}
                        className="h-7 px-2"
                      >
                        {showOnlyTopLevel ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
                      </Button>
                    )}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="pt-0">
                <div className="relative">
                  <div
                    className={`toc-scroll-area overflow-y-auto overflow-x-hidden ${isScrolling ? "scrolling" : ""}`}
                    style={{ maxHeight: dynamicHeight }}
                    onScroll={handleScroll}
                  >
                    <div className="space-y-1 pr-3 pb-2" style={{ minHeight: "100px" }}>
                      {renderTocItems(tocItems)}
                    </div>
                  </div>
                  <div className="scroll-indicator" />
                </div>
              </CardContent>
            </Card>
          </CollapsibleContent>
        </Collapsible>
      </div>

      {/* Desktop Sidebar */}
      <div className="hidden lg:block">
        <div
          ref={tocRef}
          className={`
            ${isFloating ? "fixed top-20 right-4 z-50 w-80 shadow-2xl" : "sticky top-6 max-w-xs"}
            transition-all duration-300
          `}
        >
          <Card className={`${isFloating ? "border-2 max-h-screen overflow-hidden" : ""}`}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2 text-lg">
                  <BookOpen className="w-5 h-5" />
                  Table of Contents
                  <Badge variant="secondary" className="text-xs">
                    {totalItems}
                  </Badge>
                </CardTitle>
                <div className="flex gap-1">
                  {totalItems > 10 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setShowOnlyTopLevel(!showOnlyTopLevel)}
                      className="h-7 w-7 p-0"
                      title={showOnlyTopLevel ? "Show all sections" : "Show only main sections"}
                    >
                      {showOnlyTopLevel ? <Eye className="h-3 w-3" /> : <EyeOff className="h-3 w-3" />}
                    </Button>
                  )}
                  {totalItems > 15 && (
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => setIsFloating(!isFloating)}
                      className="h-7 w-7 p-0"
                      title={isFloating ? "Dock to sidebar" : "Float panel"}
                    >
                      {isFloating ? <Minimize2 className="h-3 w-3" /> : <Maximize2 className="h-3 w-3" />}
                    </Button>
                  )}
                </div>
              </div>
              {showOnlyTopLevel && (
                <p className="text-xs text-muted-foreground">Showing main sections only. Click sections to expand.</p>
              )}
            </CardHeader>
            <CardContent className="pt-0 pb-4">
              <div className="relative">
                <div
                  className={`toc-scroll-area overflow-y-auto overflow-x-hidden ${isFloating ? "floating-scroll" : ""} ${isScrolling ? "scrolling" : ""}`}
                  style={{
                    maxHeight: isFloating ? `calc(${dynamicHeight} + 100px)` : dynamicHeight,
                    minHeight: "200px",
                  }}
                  onScroll={handleScroll}
                >
                  <div className="space-y-1 pr-3 pb-4" style={{ minHeight: "150px" }}>
                    {renderTocItems(tocItems)}
                  </div>
                </div>
                <div className="scroll-indicator" />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  )
}
