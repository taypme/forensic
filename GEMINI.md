# GEMINI

Guide for LLM assistants working with this repository.

## Safety
- Never run or suggest running `./forensic` on this repository; it will relocate files into category folders and delete duplicates. Only run it against external targets.
- Behavior is controlled solely by CLI flags and `<root>` (default `.`). There are no config files or env toggles; `--sanitize-underscores` is currently a no-op.
- Preserve the live logging format (`[info] [sweep NN] <relative-path>` with root-stripped paths).

## How to run
- Build: `make clean && make` (requires C11 compiler and OpenSSL), producing `./forensic` in the repo root.
- Execute (external targets only): `./forensic /abs/target --verbose [--no-content-analysis] [--no-path-refactor] [--sanitize-underscores] [--identifiers=csv]`.
- Identifiers are opt-in via `--identifiers=drupal,symfony,composer,node`; omit to skip sweep 00.

## Sweep map
0. Identifiers (opt-in) → move matches to `identified/<key>/<name>`.  
1. Scan & hash.  
2. Git archive relocation (`.git` → `.gitarchive/.gitN`).  
3. Category creation (ensures category dirs).  
4. File movement (flatten into category dirs by extension).  
5. Content analysis (skip with `--no-content-analysis`).  
6. Path-hash dedup.  
7. Path refactor (skip with `--no-path-refactor`).  
8. Filename pattern dedup.  
9. Pattern grouping (`<category>/<stub>.d/` + `manifest.json`).  
10. Empty-dir cleanup.

Categories created: `unknown`, `archive`, `c`, `javascript`, `python`, `ruby`, `php`, `markdown`, `css`, `json`, `image`, `video`, `audio`, `document`, `ebook`, `spreadsheet`, `presentation`, `design`, `model`, `cad`, `code`, `data`, `template`, `yml`, `map`, `html`, `text`. Routing is table-driven in `src/sweep_registry.c` and covers common document, ebook, spreadsheet, presentation, text/config, audio, video, image, design, 3D model, CAD, and coding-language extensions; default→`unknown`.

## Repo facts
- `Makefile`, `forensic` (built binary), `bin/unlimit` (lift core limits).  
- `include/`: headers for logging, regex loader, hashing, sweep context/registry, worker traversal, etc.  
- `src/`: sweep implementations, logging, token scanning, regex loader, worker walker, helper data (`generated/`, `.inc` samples); `.o` files are build artifacts.  

When suggesting commands, default to read-only inspection unless edits are requested, and remind operators not to point the tool at this repo.
