"use client"

import { useState } from "react"
import { Facebook, Linkedin, Twitter, Copy, Check } from "lucide-react"
import { Button } from "@/components/ui/button"
import { toast } from "@/components/ui/use-toast"

interface ShareButtonsProps {
  title: string
  slug: string
}

export function ShareButtons({ title, slug }: ShareButtonsProps) {
  const [copied, setCopied] = useState(false)

  const shareUrl = typeof window !== "undefined" ? `${window.location.origin}/posts/${slug}` : `/posts/${slug}`

  const handleCopy = () => {
    navigator.clipboard.writeText(shareUrl)
    setCopied(true)
    toast({
      title: "Link copied",
      description: "The post link has been copied to your clipboard.",
    })

    setTimeout(() => setCopied(false), 2000)
  }

  const shareOnTwitter = () => {
    window.open(
      `https://twitter.com/intent/tweet?text=${encodeURIComponent(title)}&url=${encodeURIComponent(shareUrl)}`,
      "_blank",
    )
  }

  const shareOnFacebook = () => {
    window.open(`https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(shareUrl)}`, "_blank")
  }

  const shareOnLinkedIn = () => {
    window.open(`https://www.linkedin.com/sharing/share-offsite/?url=${encodeURIComponent(shareUrl)}`, "_blank")
  }

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-sm text-muted-foreground">Share:</span>
      <Button variant="outline" size="icon" onClick={shareOnTwitter} aria-label="Share on Twitter">
        <Twitter className="h-4 w-4" />
      </Button>
      <Button variant="outline" size="icon" onClick={shareOnFacebook} aria-label="Share on Facebook">
        <Facebook className="h-4 w-4" />
      </Button>
      <Button variant="outline" size="icon" onClick={shareOnLinkedIn} aria-label="Share on LinkedIn">
        <Linkedin className="h-4 w-4" />
      </Button>
      <Button variant="outline" size="icon" onClick={handleCopy} aria-label="Copy link">
        {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
      </Button>
    </div>
  )
}
