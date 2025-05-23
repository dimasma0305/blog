import type React from "react"
import "@/app/globals.css"
import type { Metadata } from "next"
import { Inter, Roboto, Merriweather } from "next/font/google"
import { ThemeProvider } from "@/components/theme-provider"
import { Header } from "@/components/header"
import { Footer } from "@/components/footer"
import { Toaster } from "@/components/ui/toaster"
import { Analytics } from "@/components/analytics"
import { Suspense } from "react"

// Define more professional fonts
const inter = Inter({ subsets: ["latin"], display: "swap", variable: "--font-inter" })
const roboto = Roboto({
  weight: ["300", "400", "500", "700"],
  subsets: ["latin"],
  display: "swap",
  variable: "--font-roboto",
})
const merriweather = Merriweather({
  weight: ["300", "400", "700"],
  subsets: ["latin"],
  display: "swap",
  variable: "--font-merriweather",
})
const firaCode = Inter({
  subsets: ["latin"],
  display: "swap",
  variable: "--font-fira-code",
})

export const metadata: Metadata = {
  title: {
    default: "Dimas Maulana | Cybersecurity Researcher & CTF Player",
    template: "%s | Dimas Maulana",
  },
  description:
    "Personal website of Dimas Maulana, a cybersecurity researcher, CTF player, gamer, and manga enthusiast from Indonesia.",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://dimas.ma.id",
    siteName: "Dimas Maulana",
    title: "Dimas Maulana | Cybersecurity Researcher & CTF Player",
    description:
      "Personal website of Dimas Maulana, a cybersecurity researcher, CTF player, gamer, and manga enthusiast from Indonesia.",
    images: [
      {
        url: "/og-image.jpg",
        width: 1200,
        height: 630,
        alt: "Dimas Maulana",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "Dimas Maulana | Cybersecurity Researcher & CTF Player",
    description:
      "Personal website of Dimas Maulana, a cybersecurity researcher, CTF player, gamer, and manga enthusiast from Indonesia.",
    creator: "@dimasma___",
    images: ["/og-image.jpg"],
  },
    generator: 'v0.dev'
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${inter.variable} ${roboto.variable} ${merriweather.variable} ${firaCode.variable} font-roboto`}
      >
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem disableTransitionOnChange>
          <div className="flex flex-col min-h-screen">
            <Header />
            <Suspense>
              <main className="flex-1">{children}</main>
            </Suspense>
            <Footer />
          </div>
          <Toaster />
        </ThemeProvider>
        <Analytics />
      </body>
    </html>
  )
}
