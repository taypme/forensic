# Forensic

Forensic is a single C11 binary that sweeps a target directory and normalizes it through a fixed sequence of passes: optional framework identification, hashing, git relocation, category routing, token analysis, in-file path refactoring, duplicate cleanup, and pattern grouping. It flattens files into per-category folders and writes progress with lightweight live logging.

## Build
- Requirements: GCC or Clang with C11 support, OpenSSL (EVP SHA-256), and a POSIX-like environment.
- Build: `make clean && make` produces the `./forensic` binary in the repo root (object files land in `src/`). Use `make clean` to drop build artifacts.
- Tests: `make test` runs the unit test suite for command-line argument parsing. See `tests/README.md` for details.
- Utility: `bin/unlimit` removes core dump limits if you need crash dumps during debugging.

## Usage
```
./forensic <root> [--verbose] [--no-content-analysis] [--no-path-refactor] [--sanitize-underscores] [--identifiers=csv] [--structured-data-copy-to=<path>]
```
- `<root>` defaults to `.` and is resolved to an absolute path.
- `--verbose` enables debug logging.
- `--no-content-analysis` skips the token scan sweep.
- `--no-path-refactor` skips in-file path rewrites.
- `--sanitize-underscores` is parsed but currently unused by any sweep.
- `--identifiers=drupal,symfony` opt-in framework detection; omit to skip sweep 00 entirely.
- `--structured-data-copy-to=<path>` copies structured files to the specified destination path while leaving originals in place. The destination directory will be created if it doesn't exist. Also accepts `structured-data-copy-to=<path>` format (without `--` prefix).
- **Do not run the tool against this repository itself** unless you intentionally want it to move files into category folders and delete duplicates.

## Sweep Pipeline (in order)
0. **Identifiers** (opt-in): searches for composer/symfony/drupal/node markers and moves matched projects to `identified/<key>/<name>`, exempting them from later sweeps.  
1. **Scan & hash**: walks the tree (skipping `.git`, `.gitarchive`, `identified`) and logs SHA-256 hashes.  
2. **Git archive relocation**: moves nested `.git` directories into `<root>/.gitarchive/.gitN`.  
3. **Category creation**: ensures category directories exist: `unknown`, `archive`, `c`, `javascript`, `python`, `ruby`, `php`, `markdown`, `css`, `json`, `image`, `data`, `template`, `yml`, `map`, `html`, `text`, `java`, `music`, `executable`.  
4. **File movement**: flattens files into the matching category directory based on extension (e.g., `.js/.ts/.mjs/.cjs`→`javascript`, `.py`→`python`, `.php/.module/.install`→`php`, `.png/.jpg/.svg/.ico/.gif/.pdf/.webp/.avif`→`image`, `.java/.class/.kt`→`java`, `.mp3/.mp4/.wav/.ogg/.mov/.avi`→`music`, `.exe/.bin/.sh/.bat/.app`→`executable`; unrecognized → `unknown`). When `--structured-data-copy-to` is specified, files are copied to the destination with the structured folder organization while originals remain unchanged in their current locations.  
5. **Content analysis**: when enabled, scans files ≤512 KB for path-like tokens using built-in regexes (or overrides in `<root>/regex/`), collects unique tokens, and logs counts.  
6. **Path-hash dedup**: hashes the collected tokens and logs unique counts.  
7. **Path refactor**: when enabled, rewrites path-like tokens in-place to be relative to `<root>` when they resolve inside the tree, then writes the modified files.  
8. **Filename pattern dedup**: deletes duplicate files that share a sanitized basename/category and identical content.  
9. **Pattern grouping**: moves related variants into `<category>/<stub>.d/`, renaming them with numeric suffixes and writing a `manifest.json`.  
10. **Empty-dir cleanup**: removes empty directories after all other moves.

Live logging: sweep start lines show `[sweep NN]`; progress stays on one terminal line as `[info] [sweep NN] <relative-path>` with the current root stripped from displayed paths.

## Repository Layout
- `Makefile`: minimal build script linking against OpenSSL.  
- `forensic`: built binary (may be stale).  
- `bin/unlimit`: helper to lift `ulimit -c` caps.  
- `include/`: headers for logging, regex loading, hashing, sweep context/registry, worker traversal, etc.  
- `src/`: implementation of sweeps, logging, token scanning, regex loader, hashing, worker walker, and helper data (`generated/` holds default pattern lists; `.o` files are build artifacts).  
- `src/categories.inc`, `src/paths_regex.inc`: sample/generated data used by helper components.  

Run `make clean && make` before distributing the binary to ensure a fresh build.
