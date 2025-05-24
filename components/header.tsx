"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { motion } from "framer-motion"
import { Menu, X, Shield, BookOpen, Search } from "lucide-react"

import { Button } from "@/components/ui/button"
import { ThemeToggle } from "@/components/theme-toggle"

const navItems = [
  { name: "Home", path: "/", icon: <Shield className="w-4 h-4" /> },
  { name: "About", path: "/#about", icon: <BookOpen className="w-4 h-4" /> },
  { name: "Skills", path: "/#skills", icon: <Shield className="w-4 h-4" /> },
  { name: "Experience", path: "/#experience", icon: <Shield className="w-4 h-4" /> },
  { name: "Projects", path: "/#projects", icon: <BookOpen className="w-4 h-4" /> },
  { name: "CTF", path: "/#ctf", icon: <Shield className="w-4 h-4" /> },
  { name: "Blog", path: "/blog", icon: <BookOpen className="w-4 h-4" /> },
  { name: "Search", path: "/search", icon: <Search className="w-4 h-4" /> },
]

export function Header() {
  const [isOpen, setIsOpen] = useState(false)
  const [isScrolled, setIsScrolled] = useState(false)
  const pathname = usePathname()
  const [activeItem, setActiveItem] = useState("/")

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 10)
    }

    const handleHashChange = () => {
      const hash = window.location.hash || "/"
      setActiveItem(hash)
    }

    window.addEventListener("scroll", handleScroll)
    window.addEventListener("hashchange", handleHashChange)

    return () => {
      window.removeEventListener("scroll", handleScroll)
      window.removeEventListener("hashchange", handleHashChange)
    }
  }, [])

  useEffect(() => {
    // Close mobile menu when route changes
    setIsOpen(false)
  }, [pathname])

  return (
    <header
      className={`sticky top-0 z-40 w-full transition-all ${
        isScrolled ? "bg-background/80 backdrop-blur-md shadow-md" : "bg-transparent"
      }`}
    >
      <div className="container flex items-center justify-between h-16 px-4 mx-auto max-w-7xl">
        <Link href="/" className="flex items-center space-x-2">
          <motion.div
            initial={{ opacity: 0, scale: 0.8 }}
            animate={{ opacity: 1, scale: 1 }}
            transition={{ duration: 0.3 }}
          >
            <span className="text-2xl font-bold">Dimas Maulana</span>
          </motion.div>
        </Link>

        <div className="hidden md:flex md:items-center md:space-x-1">
          <nav className="flex items-center">
            {navItems.map((item) => (
              <Link key={item.path} href={item.path}>
                <Button
                  variant="ghost"
                  className={`group relative overflow-hidden ${
                    (pathname === item.path || (item.path !== "/" && pathname.startsWith(item.path))) 
                      ? "text-primary" 
                      : ""
                  }`}
                >
                  <span className="flex items-center gap-2">
                    {item.icon}
                    {item.name}
                  </span>
                  <span
                    className={`absolute bottom-0 left-0 w-full h-0.5 bg-primary transform origin-left transition-transform duration-300 ${
                      (pathname === item.path || (item.path !== "/" && pathname.startsWith(item.path)))
                        ? "scale-x-100" 
                        : "scale-x-0"
                    } group-hover:scale-x-100`}
                  />
                </Button>
              </Link>
            ))}
          </nav>

          <div className="flex items-center space-x-2">
            <ThemeToggle />
          </div>
        </div>

        <div className="flex items-center md:hidden">
          <ThemeToggle />
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setIsOpen(!isOpen)}
            aria-label="Toggle Menu"
            className="ml-2"
          >
            {isOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
          </Button>
        </div>
      </div>

      {/* Mobile menu */}
      {isOpen && (
        <div className="md:hidden bg-background/95 backdrop-blur-md">
          <div className="container px-4 py-4 mx-auto">
            <nav className="flex flex-col space-y-1">
              {navItems.map((item) => (
                <Link key={item.path} href={item.path}>
                  <Button
                    variant="ghost"
                    className={`w-full justify-start ${
                      (pathname === item.path || (item.path !== "/" && pathname.startsWith(item.path)))
                        ? "bg-primary/20 text-primary" 
                        : ""
                    }`}
                  >
                    <span className="flex items-center gap-2">
                      {item.icon}
                      {item.name}
                    </span>
                  </Button>
                </Link>
              ))}
            </nav>
          </div>
        </div>
      )}
    </header>
  )
}
