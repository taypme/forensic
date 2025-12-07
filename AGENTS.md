# AGENTS

Working notes for anyone operating or modifying the Forensic coordinator in this repository.

- **Do not run `./forensic` on this repository itself** unless you deliberately want it to flatten files into category folders and delete duplicates. Always point it at an external target.
- Behavior is controlled only by CLI flags and the `<root>` argument (default `.`). No config files or environment toggles are read; `--sanitize-underscores` is currently a no-op.
- Build with `make clean && make` (requires C11 compiler and OpenSSL). The resulting binary sits at `./forensic`; object files are left in `src/`.
- Logging: sweep start lines are `[sweep NN] …`; live progress stays on one terminal line as `[info] [sweep NN] <relative-path>`, with paths made relative to the current root.

## Sweep Guide
0. **Identifiers** (opt-in via `--identifiers=csv`): detect composer/symfony/drupal/node markers and move hits to `identified/<key>/<name>`, excluding them from later sweeps.  
1. **Scan & hash**: walk the tree (skipping `.git`, `.gitarchive`, `identified`) and log SHA-256 hashes.  
2. **Git archive relocation**: move nested `.git` dirs into `<root>/.gitarchive/.gitN`.  
3. **Category creation**: ensure category dirs exist.  
4. **File movement**: flatten files into category dirs based on extension.  
5. **Content analysis**: optional token scan (≤512 KB files) using built-in or `<root>/regex/` patterns.  
6. **Path-hash dedup**: hash collected tokens and log counts.  
7. **Path refactor**: optional in-file path rewrites to relative form rooted at `<root>`.  
8. **Filename pattern dedup**: delete duplicate files that share sanitized names and content.  
9. **Pattern grouping**: move variants into `<category>/<stub>.d/` and emit `manifest.json`.  
10. **Empty-dir cleanup**: remove empty directories at the end.

Categories created by sweep 03: `unknown`, `archive`, `c`, `javascript`, `python`, `ruby`, `php`, `markdown`, `css`, `json`, `image`, `data`, `template`, `yml`, `map`, `html`, `text`. Routing uses extensions: `.js/.ts`→`javascript`, `.py`→`python`, `.rb`→`ruby`, `.php/.module/.install`→`php`, `.md`→`markdown`, `.css/.scss/.less`→`css`, `.json`→`json`, common image formats → `image`, `.xml/.csv/.sql`→`data`, `.twig/.tpl.php`→`template`, `.yml/.yaml`→`yml`, `.map`→`map`, `.html`→`html`, `.txt/.markdown`→`text`, default → `unknown`.

## Repo Pointers
- `Makefile` – minimal build script linking against OpenSSL.  
- `forensic` – built binary (may be stale).  
- `bin/unlimit` – helper to lift core dump limits.  
- `include/` – headers for logging, regex loader, hashing, sweeps, worker traversal, etc.  
- `src/` – sweep implementations, logging, hashing, token scanning, regex loader, worker walker, helper data (`generated/`, `.inc` samples).  
- No historical snapshots or markdown guides are present; everything lives under `src/` and `include/`.
