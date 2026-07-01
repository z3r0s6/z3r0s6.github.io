// @ts-check
import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  // User GitHub Pages site (served at the root).
  site: 'https://z3r0s6.github.io',
  markdown: {
    shikiConfig: {
      // Dark code-block theme to match the site.
      theme: 'github-dark',
      wrap: true,
    },
  },
});
