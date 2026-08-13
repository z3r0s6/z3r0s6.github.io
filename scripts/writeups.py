#!/usr/bin/env python3
"""
Writeup manager for MACHINES and CHALLENGES (not blog posts).

Machines/challenges are not hidden with a draft flag. They are AES-encrypted at
build time (see scripts/encrypt.mjs) so an active box stays spoiler-free. A
writeup is made public by inserting a marker span in its markdown:

    <span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>

  - marker PRESENT  -> writeup is PUBLIC  (🔓)  = "password removed" / retired
  - marker ABSENT   -> writeup is LOCKED  (🔒)  = encrypted on the site

This tool:
  - list                        show machines + challenges and their lock state
  - add                         create a machine/challenge from a logo + a .md file
  - unlock <sel>  (a.k.a retire) remove the password (make public)
  - lock   <sel>                re-protect with the password
  - deploy [msg]                build, commit & push (scoped to machines/challenges/logos)

Usage:
    python3 scripts/writeups.py                 # interactive menu
    python3 scripts/writeups.py list
    python3 scripts/writeups.py add
    python3 scripts/writeups.py unlock connected
    python3 scripts/writeups.py deploy "retire Connected"
"""

import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import date

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONTENT = os.path.join(REPO_ROOT, "src", "content")
LOGOS_DIR = os.path.join(REPO_ROOT, "public", "logos")
SECTIONS = ("machines", "challenges")

# Must match scripts/manage.mjs and scripts/encrypt.mjs exactly.
MARKER = '<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>'
MARKER_KEY = "Z3R0S_NO_PASSWORD_PLEASE"

# ---- ANSI helpers ----------------------------------------------------------
_TTY = sys.stdout.isatty()
def _c(code, s): return f"\033[{code}m{s}\033[0m" if _TTY else s
def green(s):  return _c("32", s)
def yellow(s): return _c("33", s)
def cyan(s):   return _c("36", s)
def dim(s):    return _c("2", s)
def bold(s):   return _c("1", s)
def red(s):    return _c("31", s)


@dataclass
class Writeup:
    section: str          # "machines" | "challenges"
    slug: str
    path: str
    title: str
    date: date | None
    locked: bool          # True = encrypted/active, False = public/retired
    featured: str | None  # featuredImage value, e.g. /logos/Foo.png
    logo_ok: bool         # does the featured logo file exist on disk?

    @property
    def name(self) -> str:
        return f"{self.section[:-1]}/{self.slug}"   # machine/connected


FRONTMATTER_RE = re.compile(r"^﻿?---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)


def _field(block: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+?)\s*$", block, re.MULTILINE)
    return m.group(1).strip().strip('"').strip("'") if m else None


def parse_date(raw: str | None) -> date | None:
    if not raw:
        return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if not m:
        return None
    try:
        return date(*(int(x) for x in m.groups()))
    except ValueError:
        return None


def load_section(section: str) -> list[Writeup]:
    d = os.path.join(CONTENT, section)
    out: list[Writeup] = []
    if not os.path.isdir(d):
        return out
    for name in os.listdir(d):
        if not name.endswith(".md") or name.endswith("-link.md"):
            continue
        path = os.path.join(d, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        m = FRONTMATTER_RE.match(text)
        block = m.group(1) if m else ""
        featured = _field(block, "featuredImage")
        logo_ok = False
        if featured:
            logo_ok = os.path.isfile(os.path.join(REPO_ROOT, "public", featured.lstrip("/")))
        out.append(Writeup(
            section=section,
            slug=name[:-3],
            path=path,
            title=_field(block, "title") or name,
            date=parse_date(_field(block, "date")),
            locked=MARKER_KEY not in text,
            featured=featured,
            logo_ok=logo_ok,
        ))
    out.sort(key=lambda w: w.date.toordinal() if w.date else 0, reverse=True)
    return out


def load_all() -> list[Writeup]:
    return load_section("machines") + load_section("challenges")


# ---- lock / unlock (mirror manage.mjs) -------------------------------------
def add_marker(text: str) -> str:
    m = FRONTMATTER_RE.match(text)
    if not m:
        return f"{MARKER}\n\n{text}"
    idx = m.end()
    return text[:idx] + f"\n{MARKER}\n" + text[idx:]


def remove_marker(text: str) -> str:
    lines = [ln for ln in text.split("\n") if MARKER_KEY not in ln]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines))


def set_public(w: Writeup, public: bool) -> str:
    """public=True -> remove password (add marker). Returns 'changed'|'nochange'."""
    with open(w.path, encoding="utf-8") as fh:
        text = fh.read()
    has = MARKER_KEY in text
    if public and has:
        return "nochange"
    if not public and not has:
        return "nochange"
    new = add_marker(text) if public else remove_marker(text)
    if new == text:
        return "nochange"
    with open(w.path, "w", encoding="utf-8") as fh:
        fh.write(new)
    return "changed"


# ---- rendering -------------------------------------------------------------
def badge(w: Writeup) -> str:
    return red("🔒 LOCKED") if w.locked else green("🔓 PUBLIC")


def print_table(items: list[Writeup]) -> list[Writeup]:
    print()
    print(bold("  #   Kind        Lock        Logo   Date         Title"))
    print(dim("  " + "-" * 74))
    for i, w in enumerate(items, 1):
        kind = "machine" if w.section == "machines" else "challenge"
        d = w.date.isoformat() if w.date else "    -     "
        if w.section == "machines":
            logo = green("ok  ") if w.logo_ok else (yellow("MISS") if w.featured else dim("none"))
        else:
            logo = dim("  - ")
        title = w.title if len(w.title) <= 34 else w.title[:31] + "..."
        print(f"  {i:<3} {kind:<10}  {badge(w)}  {logo}   {d}   {title}")
    print(dim("  " + "-" * 74))
    m = [w for w in items if w.section == "machines"]
    c = [w for w in items if w.section == "challenges"]
    lk = sum(1 for w in items if w.locked)
    print(dim(f"  {len(m)} machines, {len(c)} challenges  |  {lk} locked, {len(items)-lk} public"))
    print()
    return items


# ---- selection: numbers, ranges, or slug/title substrings ------------------
def resolve_targets(arg: str, items: list[Writeup]) -> list[Writeup]:
    picked: list[int] = []
    for tok in arg.replace(" ", "").split(","):
        if not tok:
            continue
        if re.fullmatch(r"\d+", tok):
            n = int(tok)
            if 1 <= n <= len(items):
                picked.append(n - 1)
        elif re.fullmatch(r"\d+-\d+", tok):
            a, b = (int(x) for x in tok.split("-"))
            picked += [n - 1 for n in range(a, b + 1) if 1 <= n <= len(items)]
        else:
            low = tok.lower()
            for idx, w in enumerate(items):
                if low in w.slug.lower() or low in w.title.lower():
                    picked.append(idx)
    seen, out = set(), []
    for n in picked:
        if n not in seen:
            seen.add(n)
            out.append(items[n])
    return out


# ---- add a new writeup -----------------------------------------------------
def _ask(prompt: str, default: str = "") -> str:
    raw = input(f"{prompt}" + (f" [{default}]" if default else "") + ": ").strip()
    return raw or default


def slugify(s: str) -> str:
    return re.sub(r"^-+|-+$", "", re.sub(r"[^a-z0-9]+", "-", s.lower().strip()))


def strip_frontmatter(text: str):
    """Return (body_without_frontmatter, source_frontmatter_block_or_'')."""
    m = FRONTMATTER_RE.match(text)
    if not m:
        return text, ""
    return text[m.end():], m.group(1)


def add() -> None:
    print(bold("\nAdd a machine or challenge\n"))
    kind = _ask("Type (machine / challenge)", "machine").lower()
    section = {"machine": "machines", "machines": "machines",
               "challenge": "challenges", "challenges": "challenges"}.get(kind)
    if not section:
        print(red(f"unknown type: {kind}"))
        return

    # Body .md file (required) — pull defaults from its frontmatter if it has any.
    body_src = _ask("Path to the writeup .md file").strip().strip('"').strip("'")
    body_src = os.path.expanduser(body_src)
    if not body_src or not os.path.isfile(body_src):
        print(red(f"markdown file not found: {body_src}"))
        return
    with open(body_src, encoding="utf-8") as fh:
        src_text = fh.read()
    body, src_fm = strip_frontmatter(src_text)

    def_title = _field(src_fm, "title") or ""
    title = _ask("Title", def_title)
    if not title:
        print(red("title is required"))
        return
    slug = slugify(_ask("Slug", slugify(title)))
    dest = os.path.join(CONTENT, section, f"{slug}.md")
    if os.path.exists(dest):
        print(red(f"already exists: {section}/{slug}.md"))
        return

    the_date = _ask("Date (YYYY-MM-DD)", _field(src_fm, "date") or date.today().isoformat())
    author = _ask("Author", _field(src_fm, "author") or "z3r0s")
    def_tags = _field(src_fm, "tags")
    if def_tags:
        def_tags = def_tags.strip("[]").replace('"', "").strip()
    tags_raw = _ask("Tags (comma separated)",
                    def_tags or ("HackTheBox,Linux" if section == "machines" else ""))
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    fm = ["---", f'title: "{title.replace(chr(34), chr(92) + chr(34))}"', f"date: {the_date}",
          f"tags: [{', '.join(f'\"{t}\"' for t in tags)}]",
          'categories: ["Machines&Challenges"]']

    if section == "machines":
        difficulty = _ask("Difficulty", _field(src_fm, "difficulty") or "Easy")
        os_name = _ask("OS", _field(src_fm, "os") or "Linux")
        fm.append(f'difficulty: "{difficulty}"')
        fm.append(f'os: "{os_name}"')

    fm.append(f'author: "{author}"')

    # Logo (machines) — copy the image into public/logos/ and set featuredImage.
    featured = None
    if section == "machines":
        logo_src = _ask("Path to the logo image (optional)").strip().strip('"').strip("'")
        logo_src = os.path.expanduser(logo_src)
        if logo_src:
            if not os.path.isfile(logo_src):
                print(red(f"logo not found: {logo_src}  — creating post without a logo"))
            else:
                ext = os.path.splitext(logo_src)[1] or ".png"
                default_name = f"{slug}{ext}"
                logo_name = _ask("Save logo as (filename in public/logos/)", default_name)
                os.makedirs(LOGOS_DIR, exist_ok=True)
                shutil.copy2(logo_src, os.path.join(LOGOS_DIR, logo_name))
                featured = f"/logos/{logo_name}"
                fm.append(f'featuredImage: "{featured}"')
                print(green(f"  copied logo -> public/logos/{logo_name}"))

    fm.append("---")

    # Password: locked by default (encrypted on the site). Marker only if public.
    protect = _ask("Password-protect (lock) this writeup? (Y/n)", "Y").lower()
    marker_block = "" if not protect.startswith("n") else f"\n{MARKER}\n"

    os.makedirs(os.path.dirname(dest), exist_ok=True)
    with open(dest, "w", encoding="utf-8") as fh:
        fh.write("\n".join(fm) + "\n" + marker_block + "\n" + body.lstrip("\n"))

    print(green(f"\n✅ created {os.path.relpath(dest, REPO_ROOT)}"))
    print(dim("   " + ("🔒 LOCKED (encrypted on the site) — run `unlock` when retired."
                       if marker_block == "" else "🔓 PUBLIC (no password).")))
    if featured:
        print(dim(f"   logo: {featured}"))
    print(dim("   preview: npm run dev   |   publish: deploy"))


# ---- git / deploy (scoped to machines/challenges/logos) --------------------
def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO_ROOT, text=True, capture_output=True, check=check)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run(["git", *args], check=check)


def preflight() -> str | None:
    if run(["git", "rev-parse", "--is-inside-work-tree"], check=False).returncode != 0:
        return "not inside a git repository"
    if run(["gh", "--version"], check=False).returncode != 0:
        return "GitHub CLI (gh) not found. Install it: https://cli.github.com"
    if run(["gh", "auth", "status"], check=False).returncode != 0:
        return "gh is not logged in. Run: gh auth login"
    return None


# Only these path prefixes are ever staged by this tool's deploy.
SCOPE = ("src/content/machines/", "src/content/challenges/", "public/logos/")


def deploy(message: str | None = None) -> None:
    err = preflight()
    if err:
        print(red(f"cannot deploy: {err}"))
        return

    # Show what changed within our scope.
    st = git("status", "--porcelain", "--", "src/content/machines",
             "src/content/challenges", "public/logos").stdout.splitlines()
    if not st:
        print(dim("nothing to deploy (no machine/challenge/logo changes)."))
        return

    print(bold("\nDeploy plan  (machines / challenges / logos only):"))
    for line in st:
        xy, path = line[:2], line[3:]
        tag = {"??": "new ", " M": "edit", "M ": "edit", "MM": "edit",
               " D": "del ", "D ": "del ", "A ": "new "}.get(xy, xy)
        print(f"    {tag}  {path}")
    print(dim("\n  note: LOCKED writeups are encrypted on the site, but their markdown"))
    print(dim("        source is committed to the (public) repo — same as `npm run deploy`."))

    if input(bold("\nType 'deploy' to build, commit and push: ")).strip().lower() != "deploy":
        print(dim("cancelled"))
        return

    print(dim("validating build (astro build)..."))
    b = run(["npx", "astro", "build"], check=False)
    if b.returncode != 0:
        print(red("build FAILED, nothing pushed. tail:"))
        print((b.stdout + b.stderr)[-1500:])
        return

    # Stage ONLY our scope (never `git add -A`; never touches posts/pages).
    git("add", "--", "src/content/machines", "src/content/challenges", "public/logos")

    staged = git("diff", "--cached", "--name-only").stdout.splitlines()
    stray = [s for s in staged if not s.startswith(SCOPE)]
    if stray:
        print(red("ABORT: something outside machines/challenges/logos got staged:"))
        for s in stray:
            print(red(f"    {s}"))
        git("reset")
        print(dim("unstaged everything. nothing pushed."))
        return
    if not staged:
        print(dim("no staged changes. nothing pushed."))
        return

    if not message:
        message = "content update (machines/challenges)"
    cm = git("commit", "-m", message, check=False)
    if cm.returncode != 0:
        print(red("commit failed:"))
        print(cm.stdout + cm.stderr)
        return
    print(green(f"committed: {message}"))

    branch = git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    print(dim(f"pushing to origin/{branch}..."))
    pu = git("push", "origin", branch, check=False)
    if pu.returncode != 0:
        print(red("push failed (commit is saved locally):"))
        print(pu.stdout + pu.stderr)
        return
    print(green("pushed. GitHub Actions is building & deploying to Pages."))
    print(dim("  watch:  gh run watch"))


# ---- interactive -----------------------------------------------------------
HELP = """
Commands:
  list                 reprint the table
  add                  create a machine/challenge (asks for logo + .md paths)
  unlock <sel>         remove the password / make PUBLIC  (use when a box retires)
  retire <sel>         alias for unlock
  lock   <sel>         re-protect with the password (make LOCKED again)
  deploy [msg]         build, commit & push (machines/challenges/logos only)
  help                 show this
  quit                 exit

<sel> = list number(s) or a name: e.g.  unlock 3   |   unlock connected   |   lock 2,4-5
"""


def interactive() -> None:
    print(bold("\n=== Writeup Manager (machines & challenges) ==="))
    print(dim(HELP))
    items = print_table(load_all())

    while True:
        try:
            raw = input(cyan("writeups> ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if not raw:
            continue
        cmd, _, arg = raw.partition(" ")
        cmd = cmd.lower()

        if cmd in ("q", "quit", "exit"):
            return
        if cmd in ("h", "help", "?"):
            print(dim(HELP)); continue
        if cmd in ("l", "list", "ls"):
            items = print_table(load_all()); continue
        if cmd in ("add", "new"):
            add(); items = print_table(load_all()); continue
        if cmd in ("deploy", "push"):
            deploy(arg.strip() or None); items = print_table(load_all()); continue

        if cmd not in ("unlock", "retire", "lock"):
            print(red(f"unknown command: {cmd}  (type 'help')")); continue

        targets = resolve_targets(arg, items)
        if not targets:
            print(red("no match. example: unlock 3  or  unlock connected")); continue
        public = cmd in ("unlock", "retire")
        verb = "unlocked (now PUBLIC)" if public else "locked (now protected)"
        for w in targets:
            res = set_public(w, public)
            mark = green(verb) if res == "changed" else dim("no change")
            print(f"  {mark}  {w.name}")
        items = print_table(load_all())


def main() -> None:
    if not os.path.isdir(CONTENT):
        sys.exit(f"content dir not found: {CONTENT}")
    argv = sys.argv[1:]
    if argv and argv[0] in ("list", "ls"):
        print_table(load_all()); return
    if argv and argv[0] in ("add", "new"):
        add(); return
    if argv and argv[0] in ("deploy", "push"):
        deploy(" ".join(argv[1:]) or None); return
    if argv and argv[0] in ("unlock", "retire", "lock"):
        items = load_all()
        targets = resolve_targets(" ".join(argv[1:]), items)
        if not targets:
            print(red("no match.")); return
        public = argv[0] in ("unlock", "retire")
        for w in targets:
            res = set_public(w, public)
            state = "PUBLIC" if public else "LOCKED"
            print((green if res == "changed" else dim)(f"  {w.name} -> {state} ({res})"))
        return
    interactive()


if __name__ == "__main__":
    main()
