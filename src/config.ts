// ..............................................................
//  Edit this file to personalize your site. Everything the
//  templates render (name, bio, links) comes from here.
// ..............................................................

export const SITE = {
  title: 'z3r0s',
  description: 'Technical writeups, walkthroughs, some research and more.',
  author: 'z3r0s',
  avatar: '/images/avatar-new.jpg',
  // Used to build absolute URLs. Change when you deploy.
  url: 'https://z3r0s6.github.io',
};

// Short intro shown on the homepage.
export const ABOUT = `16 yo aspiring Red Teamer specializing in web & network penetration testing and Active Directory exploitation. I write HackTheBox writeups, CTF walkthroughs, and security research.`;

// ── Password protecting writeups ──────────────────────────────
// Machine and challenge writeups are AES-encrypted in the built site
// until the box/challenge is retired. To publish one immediately,
// add this marker anywhere in its Markdown body:
//   <span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
// (See scripts/encrypt.mjs and keep this in sync with that file.)
export const WRITEUP_PASSWORD = 'Z3R0S{IH4TESPOILERS}';

// "Where to Find Me" links. Add/remove freely.
export const SOCIALS: { label: string; href: string; handle?: string }[] = [
  { label: 'GitHub',     href: 'https://github.com/z3r0s6',                handle: '@z3r0s6' },
  { label: 'HackTheBox', href: 'https://app.hackthebox.com/users/2418277', handle: 'z3r0s' },
  { label: 'LinkedIn',   href: 'https://www.linkedin.com/in/z3r0s6/',      handle: 'z3r0s6' },
];
