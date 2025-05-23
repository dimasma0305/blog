# GitHub Pages Deployment Guide

This guide covers deploying your SEO-optimized blog to GitHub Pages with automatic CI/CD.

## 🚀 Quick Start

### 1. Repository Setup
```bash
# Push your code to GitHub
git add .
git commit -m "feat: SEO-optimized blog ready for GitHub Pages"
git push origin main
```

### 2. Enable GitHub Pages
1. Go to your repository settings
2. Navigate to **Pages** section
3. Source: **GitHub Actions**
4. The workflow will automatically deploy on push to `main`

### 3. Verify Deployment
Once deployed, your site will be available at:
```
https://dimasma0305.github.io/
```

## 📁 Files Configured for GitHub Pages

### ✅ Next.js Configuration (`next.config.js`)
- **Static Export**: `output: 'export'`
- **GitHub Pages Compatible**: Proper base path and asset prefix
- **Optimized Images**: Unoptimized for static hosting
- **Trailing Slash**: Enabled for better GitHub Pages compatibility

### ✅ GitHub Actions Workflow (`.github/workflows/deploy.yml`)
**Automated Process:**
1. **Checkout code** from main branch
2. **Install dependencies** with npm ci
3. **Generate SEO files** (index.json + sitemap.xml)
4. **Build static site** with npm run build
5. **Deploy to GitHub Pages** automatically

### ✅ SEO Files Updated
- **Sitemap**: `https://dimasma0305.github.io/sitemap.xml` (22 URLs)
- **Robots.txt**: `https://dimasma0305.github.io/robots.txt`
- **Meta Tags**: All URLs point to GitHub Pages domain
- **Structured Data**: Updated with correct base URL

## 🔍 SEO Features for GitHub Pages

### 📊 Current Status
- **14 Blog Posts** with full SEO metadata
- **5 Category Pages** properly indexed
- **22 Total URLs** in sitemap
- **All Posts** have Notion integration links
- **Structured Data** for rich snippets

### 🎯 Meta Tags Generated
Each post includes:
```html
<title>Post Title | Dimas Maulana</title>
<meta name="description" content="Clean excerpt..." />
<meta name="keywords" content="cybersecurity, CTF, categories..." />
<link rel="canonical" href="https://dimasma0305.github.io/posts/slug" />

<!-- Social Media -->
<meta property="og:url" content="https://dimasma0305.github.io/posts/slug" />
<meta property="og:image" content="https://dimasma0305.github.io/cover-image.jpg" />
<meta name="twitter:creator" content="@dimasma__" />
```

### 🗺️ Sitemap Structure
```
Homepage (Priority 1.0)
├── Blog (Priority 0.9)
├── About (Priority 0.7)
├── Categories (Priority 0.6)
│   ├── CSS Leak
│   ├── Domclobbering  
│   ├── XSS
│   ├── XXE
│   └── WordPress
└── Posts (Priority 0.8)
    ├── Patchstack CTF Writeups
    ├── RCE in Genie.jl
    ├── DOM Clobbering + CSS Leak
    └── ... (14 total posts)
```

## 🛠️ Local Development

### Development Commands
```bash
# Start development server
npm run dev

# Start with post watching
npm run dev:watch

# Generate SEO files
npm run seo:check

# Build for production
npm run build
```

### Testing Before Deployment
```bash
# 1. Generate fresh SEO files
npm run generate-index
npm run generate-sitemap

# 2. Build and test locally
npm run build
npx serve out

# 3. Verify SEO files
npm run seo:validate
```

## 📋 Post-Deployment Checklist

### ✅ Immediate Actions
- [ ] **Verify Site**: Visit `https://dimasma0305.github.io/`
- [ ] **Check Sitemap**: `https://dimasma0305.github.io/sitemap.xml`
- [ ] **Verify Robots**: `https://dimasma0305.github.io/robots.txt`
- [ ] **Test Blog**: Navigate to `/blog` and verify posts load
- [ ] **Check Notion Links**: Verify Notion badges work on post cards

### 🔍 SEO Validation
- [ ] **Google Search Console**: Submit sitemap
- [ ] **Bing Webmaster Tools**: Submit sitemap
- [ ] **Rich Results Test**: Test structured data
- [ ] **Facebook Debugger**: Test OpenGraph tags
- [ ] **Twitter Card Validator**: Test Twitter sharing

### 📱 Social Media Testing
Test these URLs in social media debuggers:
- Homepage: `https://dimasma0305.github.io/`
- Blog: `https://dimasma0305.github.io/blog/`
- Sample Post: `https://dimasma0305.github.io/posts/[any-post-slug]/`

## 🎨 Customization for GitHub Pages

### Update Domain (if you get a custom domain later)
```javascript
// scripts/generate-sitemap.js
const BASE_URL = 'https://your-custom-domain.com'

// components/seo.tsx
export function generatePostMetadata({ post, baseUrl = "https://your-custom-domain.com" })
```

### Add More Static Pages
```javascript
// scripts/generate-sitemap.js
const staticPages = [
  // existing pages...
  {
    url: `${BASE_URL}/contact`,
    lastmod: new Date().toISOString().split('T')[0],
    changefreq: 'monthly',
    priority: '0.6'
  }
]
```

## 🚨 Troubleshooting

### Build Failures
**Issue**: Build fails in GitHub Actions
**Solution**: Check that all dependencies are in package.json, not devDependencies

**Issue**: SEO files not generated
**Solution**: Ensure posts directory structure is correct:
```
public/
├── posts/
│   ├── post-slug-1/
│   │   ├── README.md
│   │   └── imgs/
│   └── post-slug-2/
│       ├── README.md
│       └── imgs/
└── sitemap.xml (generated)
```

### SEO Issues
**Issue**: Meta tags not showing in social media
**Solution**: 
1. Check if URLs are publicly accessible
2. Use Facebook Debugger to refresh cache
3. Verify OpenGraph image exists and is accessible

**Issue**: Sitemap not being crawled
**Solution**:
1. Submit manually in Google Search Console
2. Check robots.txt is accessible
3. Verify sitemap XML is valid

## 📊 Performance Monitoring

### Key Metrics to Track
- **Google Search Console**: Impressions, clicks, CTR
- **Core Web Vitals**: LCP, FID, CLS
- **Social Sharing**: Twitter/Facebook engagement
- **Notion Link Clicks**: Track external referrals

### Monthly SEO Tasks
1. **Regenerate sitemap** when adding new posts
2. **Monitor indexing status** in Search Console
3. **Check for crawl errors**
4. **Update meta descriptions** based on performance
5. **Test social media sharing** for new posts

## 🎉 Success Metrics

Your blog is successfully deployed when:
- ✅ **Site loads** at `https://dimasma0305.github.io/`
- ✅ **22 URLs** in sitemap are accessible
- ✅ **14 blog posts** have proper meta tags
- ✅ **All Notion links** work correctly
- ✅ **Social sharing** shows rich previews
- ✅ **Search Console** accepts sitemap without errors

## 🔗 Important URLs

**Live Site**: https://dimasma0305.github.io/
**Blog**: https://dimasma0305.github.io/blog/
**Sitemap**: https://dimasma0305.github.io/sitemap.xml
**Robots**: https://dimasma0305.github.io/robots.txt

**GitHub Repository**: Update this with your actual repo URL
**GitHub Actions**: Check deployment status in Actions tab

---

🚀 **Your cybersecurity blog is now optimized and ready for the world to discover on Google!** 