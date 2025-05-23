# Development Guide

This guide explains how to develop your blog without constant rebuilds and performance issues.

## 🚀 Development Commands

### Regular Development (Recommended)
```bash
npm run dev
```
**Use this for normal development work**
- Starts Next.js dev server without file watching
- No automatic index regeneration
- Faster rebuilds and better performance
- Ideal for UI development, component work, and styling

### Development with File Watching
```bash
npm run dev:watch
```
**Use only when actively editing blog posts**
- Starts Next.js dev server + file watcher
- Automatically regenerates index when posts change
- Has 3-second debounce to prevent rapid rebuilds
- More resource intensive

### Quiet Development
```bash
npm run dev:quiet
```
**Use for debugging build issues**
- Suppresses size limit warnings
- Same as regular dev but with less console output

## 🔧 Performance Optimizations

### File Watching Exclusions
The following files are ignored during development to prevent constant rebuilds:
- `public/posts/index.json` (generated file)
- `public/sitemap.xml` (generated file)
- `node_modules/` and `.git/` directories
- Temporary files (`.tmp`, `.swp`, `~` files)
- Script files that generate content

### Caching Improvements
- Filesystem caching enabled for faster rebuilds
- Reduced polling frequency (1 second intervals)
- Aggregated change detection (300ms debounce)

## 📝 Recommended Workflow

### For UI/Component Development:
1. Use `npm run dev` (no file watching)
2. Work on components, styling, and layout
3. Manually run `npm run generate-index` if you need fresh post data

### For Content/Blog Post Development:
1. Use `npm run dev:watch` to see changes in real-time
2. Edit your markdown files
3. Index automatically regenerates after 3 seconds of inactivity

### For SEO/Build Development:
1. Use `npm run dev` for main development
2. Test with `npm run seo:check` when needed
3. Build with `npm run build` to verify everything works

## 🚨 Troubleshooting Constant Rebuilds

### If you're still experiencing constant rebuilds:

1. **Check if file watcher is running:**
   ```bash
   # Kill any running file watchers
   pkill -f "watch-posts"
   
   # Use regular dev instead of dev:watch
   npm run dev
   ```

2. **Clear Next.js cache:**
   ```bash
   rm -rf .next/
   npm run dev
   ```

3. **Check for file modifications:**
   ```bash
   # Make sure these files aren't being constantly modified
   ls -la public/posts/index.json public/sitemap.xml
   ```

4. **Use git to track file changes:**
   ```bash
   git status
   # Should not show constant changes to index.json or sitemap.xml
   ```

## 📊 Development vs Production

### Development Mode (`npm run dev`)
- ✅ Fast rebuilds
- ✅ Hot module replacement
- ✅ No SEO file generation
- ✅ Optimized for coding experience

### Production Build (`npm run build`)
- ✅ Automatic SEO file generation
- ✅ Static export for GitHub Pages
- ✅ Optimized bundles
- ✅ Full sitemap and index generation

## 🔍 Debugging File Changes

If you need to see what files are changing:

```bash
# Monitor file changes in posts directory
fswatch -r public/posts/ | head -20

# Or check what Next.js is watching
DEBUG=next:* npm run dev 2>&1 | grep -i watch
```

## 💡 Best Practices

1. **Use `npm run dev` for most development work**
2. **Only use `npm run dev:watch` when actively editing posts**
3. **Run `npm run generate-index` manually when you add new posts**
4. **Use `npm run build` to test full production build**
5. **Keep the posts directory structure clean (no temporary files)**

## 🛠️ Environment Variables

You can set these in your shell to control development behavior:

```bash
# Disable turbo features if they cause issues
export NEXT_TURBO=0

# Skip size limit warnings
export NEXT_PRIVATE_SKIP_SIZE_LIMIT=1

# Enable verbose logging for debugging
export DEBUG=next:*
```

---

**Remember**: The goal is fast development cycles. Use the simplest command (`npm run dev`) that meets your current needs! 