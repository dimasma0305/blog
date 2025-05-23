# Interactive Blog

This is a interactive blog application that directly reads and displays Markdown files from the `/posts` directory.

## Features

- Reads README.md files from the `/posts` directory
- Supports Markdown content with syntax highlighting
- Responsive design
- Dark mode support
- Category filtering
- Image path processing

## Directory Structure

The blog expects posts to be organized in the following structure:

\`\`\`
/posts
  /post-slug-1
    /README.md
    /imgs
      /image1.jpg
      /image2.png
  /post-slug-2
    /README.md
    /imgs
      /image1.jpg
\`\`\`

## Markdown Format

Each README.md file should include frontmatter with metadata about the post. Example:

\`\`\`markdown
---
title: "My Blog Post Title"
created_time: "2024-05-22T00:00:00.000Z"
last_edited_time: "2024-05-22T00:00:00.000Z"
cover_image: "./imgs/cover.jpg"
icon_emoji: "📝"
categories: ["Category1", "Category2"]
---

# Post Title

This is the content of my blog post.

## Heading 2

More content here...

![Image Description](./imgs/image1.jpg)
\`\`\`

## Available Frontmatter Fields

- `title`: The title of the post
- `created_time`: The creation date (ISO format)
- `last_edited_time`: The last edit date (ISO format)
- `cover_image`: Path to the cover image (relative to the post's folder)
- `icon_emoji`: An emoji to display alongside the post
- `categories`: An array of categories
- `owner`: Object with author information (optional)

## API

The blog provides API endpoints for fetching posts:

- `GET /api/posts`: Returns all posts
- `GET /api/posts/[slug]`: Returns a specific post by slug

## Development

To run the blog locally:

\`\`\`bash
npm install
npm run dev
\`\`\`

Then visit `http://localhost:3000` to view the blog.
