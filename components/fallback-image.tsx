"use client"

import Image from "next/image"
import { useState } from "react"

interface FallbackImageProps {
  src: string
  alt: string
  width?: number
  height?: number
  fill?: boolean
  className?: string
  priority?: boolean
  fallbackSrc?: string
}

export function FallbackImage({
  src,
  alt,
  width,
  height,
  fill = false,
  className = "",
  priority = false,
  fallbackSrc,
}: FallbackImageProps) {
  const [imgSrc, setImgSrc] = useState(src)

  // Handle image load error
  const handleError = () => {
    // Use provided fallback or generate a placeholder
    const defaultFallback = `/placeholder.svg?height=${height || 400}&width=${width || 600}&text=${encodeURIComponent(alt)}`
    setImgSrc(fallbackSrc || defaultFallback)
  }

  return (
    <Image
      src={imgSrc || "/placeholder.svg"}
      alt={alt}
      width={!fill ? width : undefined}
      height={!fill ? height : undefined}
      fill={fill}
      className={className}
      priority={priority}
      onError={handleError}
    />
  )
}
