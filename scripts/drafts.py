#!/usr/bin/env python3
"""
Blog post draft manager.

Interactive tool to publish / unpublish / remove posts in
src/content/posts and see them in the order they'll appear on the site.

Publishing here ONLY flips the `draft:` flag in the file's frontmatter.
It does NOT deploy anything. Nothing leaves your machine until you run
your own git add / commit / push. So this is safe to use on embargoed
drafts: flip them to live locally, preview, flip them back.

Usage:
    python3 scripts/drafts.py            # interactive menu
    python3 scripts/drafts.py list       # print status table and exit
"""

import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
POSTS_DIR = os.path.join(REPO_ROOT, "src", "content", "posts")

# ---- tiny ANSI helpers (fall back to plain if not a tty) -------------------
_TTY = sys.stdout.isatty()
def _c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else s
def green(s):  return _c("32", s)
def yellow(s): return _c("33", s)
def cyan(s):   return _c("36", s)
def dim(s):    return _c("2", s)
def bold(s):   return _c("1", s)
def red(s):    return _c("31", s)


@dataclass
class Post:
    path: str
    title: str
    date: date | None
    draft: bool
    external: bool          # externalLink stub (nav entry, e.g. Machines/Challenges)
    weight: int
    has_draft_line: bool

    @property
    def name(self) -> str:
        return os.path.basename(self.path)


# Tolerate a leading UTF-8 BOM and a closing --- with no trailing newline (EOF).
FRONTMATTER_RE = re.compile(r"^﻿?---\s*\n(.*?)\n---\s*(?:\n|\Z)", re.DOTALL)


def _field(block: str, key: str) -> str | None:
    m = re.search(rf"^{re.escape(key)}\s*:\s*(.+?)\s*$", block, re.MULTILINE)
    if not m:
        return None
    return m.group(1).strip().strip('"').strip("'")


def parse_date(raw: str | None) -> date | None:
    if not raw:
        return None
    m = re.match(r"(\d{4})-(\d{2})-(\d{2})", raw)
    if not m:
        return None
    y, mo, d = (int(x) for x in m.groups())
    try:
        return date(y, mo, d)
    except ValueError:
        return None


def load_posts() -> list[Post]:
    posts: list[Post] = []
    for name in os.listdir(POSTS_DIR):
        if not name.endswith(".md"):
            continue
        path = os.path.join(POSTS_DIR, name)
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        m = FRONTMATTER_RE.match(text)
        block = m.group(1) if m else ""
        draft_raw = _field(block, "draft")
        posts.append(Post(
            path=path,
            title=_field(block, "title") or name,
            date=parse_date(_field(block, "date")),
            draft=(draft_raw or "").lower() == "true",
            external=_field(block, "externalLink") is not None,
            weight=int(_field(block, "weight") or 0),
            has_draft_line=draft_raw is not None,
        ))
    return posts


def site_order(posts: list[Post]) -> list[Post]:
    """Replicate src/pages/posts/index.astro ordering:
    external-link stubs first (by weight asc), then real posts newest-first."""
    def key(p: Post):
        if p.external:
            return (0, p.weight, 0)
        # negative ordinal so newer dates come first
        ordinal = p.date.toordinal() if p.date else 0
        return (1, 0, -ordinal)
    return sorted(posts, key=key)


# ---- frontmatter editing (surgical: touch only the draft: line) ------------
def set_draft(post: Post, value: bool) -> bool:
    """Return True if the file changed."""
    with open(post.path, encoding="utf-8") as fh:
        text = fh.read()
    m = FRONTMATTER_RE.match(text)
    if not m:
        print(red(f"  ! {post.name} has no frontmatter, skipping"))
        return False
    block = m.group(1)
    want = "true" if value else "false"

    if re.search(r"^draft\s*:", block, re.MULTILINE):
        new_block, n = re.subn(
            r"^(draft\s*:\s*).*$", rf"\g<1>{want}", block, flags=re.MULTILINE
        )
    else:
        # no draft line: only add one if we need draft:true; draft:false is default
        if not value:
            return False
        new_block = block.rstrip("\n") + f"\ndraft: {want}"
        n = 1

    if n == 0:
        return False
    new_text = text[:m.start(1)] + new_block + text[m.end(1):]
    if new_text == text:
        return False
    with open(post.path, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    return True


def remove_post(post: Post) -> None:
    os.remove(post.path)


# ---- git / deploy ----------------------------------------------------------
# Deploy rules (why this is careful):
#   The GitHub Actions workflow builds from the pushed source, so committing a
#   post's .md makes its markdown PUBLIC in the repo even if draft:true hides it
#   from the rendered site. Therefore:
#     - NEVER `git add -A`.
#     - `git add -u` only (stages changes to already-tracked files) + explicit
#       adds of newly-published (draft:false) untracked posts.
#     - An untracked draft:true post is embargoed and is never staged.
#     - Hard safety assertion before commit: abort if any previously-untracked
#       draft post ended up staged.
def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO_ROOT, text=True,
                          capture_output=True, check=check)


def git(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return run(["git", *args], check=check)


def rel(path: str) -> str:
    return os.path.relpath(path, REPO_ROOT)


def preflight() -> str | None:
    if run(["git", "rev-parse", "--is-inside-work-tree"], check=False).returncode != 0:
        return "not inside a git repository"
    if run(["gh", "--version"], check=False).returncode != 0:
        return "GitHub CLI (gh) not found. Install it: https://cli.github.com"
    if run(["gh", "auth", "status"], check=False).returncode != 0:
        return "gh is not logged in. Run: gh auth login"
    return None


def porcelain() -> dict[str, str]:
    out = git("status", "--porcelain").stdout.splitlines()
    res: dict[str, str] = {}
    for line in out:
        if len(line) < 4:
            continue
        res[line[3:]] = line[:2]
    return res


def image_dir_for(post: Post) -> str | None:
    d = os.path.join(REPO_ROOT, "public", "images", post.name[:-3])
    return d if os.path.isdir(d) else None


def build_plan(posts: list[Post]):
    st = porcelain()
    prels = {rel(p.path): p for p in posts}
    plan = {"publish": [], "update": [], "hide": [], "held": [], "other": []}
    for r, p in prels.items():
        xy = st.get(r)
        untracked = xy == "??"
        if not p.draft:                       # meant to be live
            if untracked:
                plan["publish"].append(p)     # brand-new public post
            elif xy is not None:
                plan["update"].append(p)       # tracked live post changed
        else:                                  # draft
            if untracked:
                plan["held"].append(p)         # embargoed, never pushed
            elif xy is not None:
                plan["hide"].append(p)         # was live, now hidden
    for r, xy in st.items():
        if r in prels or xy == "??":
            continue                           # untracked non-posts stay out
        plan["other"].append((r, xy))
    return plan, st


def do_deploy(message: str | None = None) -> None:
    err = preflight()
    if err:
        print(red(f"cannot deploy: {err}"))
        return

    posts = load_posts()
    plan, st = build_plan(posts)

    print(bold("\nDeploy plan  (origin/main):"))
    if plan["publish"]:
        print(red(bold("  NEW PUBLIC POSTS (visible to everyone once CI finishes):")))
        for p in plan["publish"]:
            print(red(f"      + {p.name}"))
    if plan["update"]:
        print(green("  update (live posts changed):"))
        for p in plan["update"]:
            print(f"      ~ {p.name}")
    if plan["hide"]:
        print(yellow("  hide (was live, now draft):"))
        for p in plan["hide"]:
            print(f"      - {p.name}")
    if plan["other"]:
        print(cyan("  other tracked changes:"))
        for r, xy in plan["other"]:
            print(f"      {xy} {r}")
    if plan["held"]:
        print(dim("  held back — embargoed drafts, NOT pushed, stay private:"))
        for p in plan["held"]:
            print(dim(f"      · {p.name}"))

    if not (plan["publish"] or plan["update"] or plan["hide"] or plan["other"]):
        print(dim("\n  nothing to deploy."))
        return

    if plan["publish"]:
        print(red("\nThese posts become permanently public on the internet."))
    if input(bold("\nType 'deploy' to build, commit and push: ")).strip().lower() != "deploy":
        print(dim("cancelled"))
        return

    print(dim("validating build (astro build)..."))
    b = run(["npx", "astro", "build"], check=False)
    if b.returncode != 0:
        print(red("build FAILED, nothing pushed. tail:"))
        print((b.stdout + b.stderr)[-1500:])
        return

    untracked_before = {r for r, xy in st.items() if xy == "??"}

    git("add", "-u")                                   # tracked changes only
    for p in plan["publish"]:                          # newly-live posts + images
        git("add", "--", rel(p.path))
        img = image_dir_for(p)
        if img:
            git("add", "--", rel(img))

    # Safety net: make sure no embargoed (previously-untracked) draft got staged.
    staged = git("diff", "--cached", "--name-only").stdout.splitlines()
    leaked = [s for s in staged
              if s in untracked_before and s.startswith("src/content/posts/")
              and s.endswith(".md")
              and next((p for p in posts if rel(p.path) == s), Post("", "", None, False, False, 0, False)).draft]
    if leaked:
        print(red("ABORT: an embargoed draft was about to be committed:"))
        for s in leaked:
            print(red(f"    {s}"))
        git("reset")
        print(dim("unstaged everything. nothing pushed."))
        return

    if not staged:
        print(dim("no staged changes after filtering. nothing pushed."))
        return

    if not message:
        if plan["publish"]:
            titles = ", ".join(p.title.split(":")[0].split(".")[0] for p in plan["publish"])
            message = f"publish: {titles}"
        else:
            message = "content update"

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
    print(dim("  watch:   gh run watch"))
    print(dim("  status:  gh run list --limit 3"))


# ---- rendering -------------------------------------------------------------
def status_badge(p: Post) -> str:
    if p.external:
        return cyan("→ LINK ")
    return green("● LIVE ") if not p.draft else yellow("○ DRAFT")


def print_table(posts: list[Post]) -> list[Post]:
    ordered = site_order(posts)
    print()
    print(bold("  #   Status    Date         Title"))
    print(dim("  " + "-" * 68))
    for i, p in enumerate(ordered, 1):
        d = p.date.isoformat() if p.date else dim("   -      ")
        title = p.title if len(p.title) <= 46 else p.title[:43] + "..."
        print(f"  {i:<3} {status_badge(p)}  {d}   {title}")
    live = sum(1 for p in ordered if not p.draft and not p.external)
    draft = sum(1 for p in ordered if p.draft and not p.external)
    print(dim("  " + "-" * 68))
    print(dim(f"  {live} live, {draft} draft "
              f"(list order = how the site shows them)"))
    print()
    return ordered


# ---- selection parsing -----------------------------------------------------
def parse_selection(arg: str, count: int) -> list[int]:
    """'1,3-5' -> [0,2,3,4] (0-based indices), silently clamps to range."""
    picked: list[int] = []
    for chunk in arg.replace(" ", "").split(","):
        if not chunk:
            continue
        if "-" in chunk:
            a, _, b = chunk.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError:
                continue
            for n in range(lo, hi + 1):
                if 1 <= n <= count:
                    picked.append(n - 1)
        else:
            try:
                n = int(chunk)
            except ValueError:
                continue
            if 1 <= n <= count:
                picked.append(n - 1)
    # de-dup, keep order
    seen, out = set(), []
    for n in picked:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


HELP = """
Commands:
  publish <sel>   flip selected posts to live   (draft: false)
  draft   <sel>   flip selected posts to draft  (draft: true)
  remove  <sel>   delete the selected files     (asks to confirm)
  deploy  [msg]   build, commit & push the live posts to GitHub (asks to confirm)
  list            reprint the table
  help            show this
  quit            exit

<sel> is by the # column: e.g.  publish 2   |   draft 3,5   |   remove 4-6
publish/draft only edit files locally. Only `deploy` pushes to GitHub.
deploy never stages an embargoed (untracked draft) post. Needs: gh installed + logged in.
"""


def interactive() -> None:
    print(bold("\n=== Blog Post Manager ==="))
    print(dim(HELP))
    ordered = print_table(load_posts())

    while True:
        try:
            raw = input(cyan("posts> ")).strip()
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
            print(dim(HELP))
            continue
        if cmd in ("l", "list", "ls"):
            ordered = print_table(load_posts())
            continue
        if cmd in ("deploy", "push"):
            do_deploy(arg.strip() or None)
            ordered = print_table(load_posts())
            continue

        if cmd not in ("publish", "draft", "remove", "rm", "unpublish"):
            print(red(f"unknown command: {cmd}  (type 'help')"))
            continue

        sel = parse_selection(arg, len(ordered))
        if not sel:
            print(red("no valid selection. example: publish 2  or  remove 4-6"))
            continue
        targets = [ordered[i] for i in sel]

        if cmd == "remove" or cmd == "rm":
            print(red("about to DELETE these files:"))
            for p in targets:
                print(f"    {p.name}")
            ok = input(red("type 'yes' to delete: ")).strip().lower()
            if ok != "yes":
                print(dim("cancelled"))
                continue
            for p in targets:
                remove_post(p)
                print(f"  {red('deleted')} {p.name}")
        else:
            value = (cmd == "draft" or cmd == "unpublish")
            verb = "drafted" if value else "published"
            for p in targets:
                if p.external:
                    print(dim(f"  skip {p.name} (nav link, not a real post)"))
                    continue
                changed = set_draft(p, value)
                mark = green(verb) if changed else dim("no change")
                print(f"  {mark} {p.name}")

        ordered = print_table(load_posts())


def main() -> None:
    if not os.path.isdir(POSTS_DIR):
        sys.exit(f"posts dir not found: {POSTS_DIR}")
    if len(sys.argv) > 1 and sys.argv[1] in ("list", "ls"):
        print_table(load_posts())
        return
    if len(sys.argv) > 1 and sys.argv[1] in ("deploy", "push"):
        do_deploy(" ".join(sys.argv[2:]) or None)
        return
    interactive()


if __name__ == "__main__":
    main()
