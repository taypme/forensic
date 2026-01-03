# Test Suite

This directory contains unit tests for the forensic tool.

## Running Tests

To run all tests:

```bash
make test
```

Or build and run manually:

```bash
make clean
make test
```

## Test Coverage

The test suite (`test_args.c`) covers all command-line argument parsing:

### Basic Flags
- `--verbose` - Enables verbose logging
- `--no-content-analysis` - Disables content analysis
- `--no-path-refactor` - Disables path refactoring
- `--sanitize-underscores` - Enables underscore sanitization

### Identifier Flags
- `--identifiers=composer` - Single identifier
- `--identifiers=composer,symfony,drupal,node` - Multiple identifiers
- `--identifiers=node` / `--identifiers=node.js` / `--identifiers=nodejs` - Node variants

### Copy Options
- `--structured-data-copy-to=<path>` - With `--` prefix
- `structured-data-copy-to=<path>` - Without `--` prefix
- Empty path validation

### Root Argument
- Default root (`.`)
- Explicit root path
- Root with all flags combined

### Error Cases
- Unknown flags
- Empty structured-data-copy-to path

## Test Framework

The tests use a simple custom framework defined in `test_args.c`. Each test:
1. Sets up test arguments
2. Calls `parse_args()`
3. Asserts expected behavior
4. Reports pass/fail

## Adding New Tests

To add a new test:

1. Create a test function: `static void test_my_feature(void)`
2. Set up test data (argv array)
3. Call `parse_args()`
4. Use `ASSERT()` macro to verify results
5. Call the test function from `main()`

Example:
```c
static void test_my_feature(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--my-flag"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "my flag should parse successfully");
    ASSERT(args.my_flag == true, "my flag should be set");
}
```

