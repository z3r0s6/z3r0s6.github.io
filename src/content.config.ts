import { defineCollection, z } from 'astro:content';
import { glob } from 'astro/loaders';

// Shared schema for writeups (machines & challenges).
const writeup = z.object({
  title: z.string(),
  date: z.coerce.date(),
  tags: z.array(z.string()).default([]),
  categories: z.array(z.string()).default([]),
  author: z.string().optional(),
  difficulty: z.string().optional(),
  os: z.string().optional(),
  featuredImage: z.string().optional(),
  draft: z.boolean().default(false),
});

const machines = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/machines' }),
  schema: writeup,
});

const challenges = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/challenges' }),
  schema: writeup,
});

const posts = defineCollection({
  loader: glob({ pattern: '**/*.md', base: './src/content/posts' }),
  schema: z.object({
    title: z.string(),
    date: z.coerce.date(),
    tags: z.array(z.string()).default([]),
    categories: z.array(z.string()).default([]),
    author: z.string().optional(),
    // Link-only posts (e.g. "Machines" -> /machines/) use this.
    externalLink: z.string().optional(),
    weight: z.number().optional(),
    draft: z.boolean().default(false),
  }),
});

export const collections = { machines, challenges, posts };
