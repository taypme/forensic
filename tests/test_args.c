#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <assert.h>
#include "../include/arg_parser.h"
#include "../include/logging.h"

// Simple test framework
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT(condition, message) \
    do { \
        tests_run++; \
        if(condition) { \
            tests_passed++; \
            printf("PASS: %s\n", message); \
        } else { \
            tests_failed++; \
            printf("FAIL: %s\n", message); \
        } \
    } while(0)

static void test_default_args(void) {
    ParsedArgs args;
    char *argv[] = {"forensic"};
    int argc = 1;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "default args should parse successfully");
    ASSERT(strcmp(args.root_arg, ".") == 0, "default root should be '.'");
    ASSERT(args.enable_content == true, "content analysis should be enabled by default");
    ASSERT(args.enable_refactor == true, "path refactor should be enabled by default");
    ASSERT(args.enable_sanitize == false, "sanitize should be disabled by default");
    ASSERT(args.ident_mask == 0, "identifiers should be disabled by default");
    ASSERT(args.copy_to_arg == NULL, "copy_to should be NULL by default");
    ASSERT(args.verbose == false, "verbose should be false by default");
}

static void test_verbose_flag(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--verbose"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "verbose flag should parse successfully");
    ASSERT(args.verbose == true, "verbose should be true");
}

static void test_no_content_analysis(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--no-content-analysis"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "no-content-analysis should parse successfully");
    ASSERT(args.enable_content == false, "content analysis should be disabled");
}

static void test_no_path_refactor(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--no-path-refactor"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "no-path-refactor should parse successfully");
    ASSERT(args.enable_refactor == false, "path refactor should be disabled");
}

static void test_sanitize_underscores(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--sanitize-underscores"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "sanitize-underscores should parse successfully");
    ASSERT(args.enable_sanitize == true, "sanitize should be enabled");
}

static void test_identifiers_single(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--identifiers=composer"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "identifiers=composer should parse successfully");
    ASSERT((args.ident_mask & (1u<<0)) != 0, "composer identifier should be set");
    ASSERT((args.ident_mask & (1u<<1)) == 0, "symfony identifier should not be set");
}

static void test_identifiers_multiple(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--identifiers=composer,symfony,drupal,node"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "identifiers with multiple values should parse successfully");
    ASSERT((args.ident_mask & (1u<<0)) != 0, "composer identifier should be set");
    ASSERT((args.ident_mask & (1u<<1)) != 0, "symfony identifier should be set");
    ASSERT((args.ident_mask & (1u<<2)) != 0, "drupal identifier should be set");
    ASSERT((args.ident_mask & (1u<<3)) != 0, "node identifier should be set");
}

static void test_identifiers_node_variants(void) {
    ParsedArgs args1, args2, args3;
    char *argv1[] = {"forensic", "--identifiers=node"};
    char *argv2[] = {"forensic", "--identifiers=node.js"};
    char *argv3[] = {"forensic", "--identifiers=nodejs"};
    
    int rc1 = parse_args(2, argv1, &args1);
    int rc2 = parse_args(2, argv2, &args2);
    int rc3 = parse_args(2, argv3, &args3);
    
    ASSERT(rc1 == 0, "identifiers=node should parse successfully");
    ASSERT(rc2 == 0, "identifiers=node.js should parse successfully");
    ASSERT(rc3 == 0, "identifiers=nodejs should parse successfully");
    ASSERT((args1.ident_mask & (1u<<3)) != 0, "node identifier should be set");
    ASSERT((args2.ident_mask & (1u<<3)) != 0, "node.js identifier should be set");
    ASSERT((args3.ident_mask & (1u<<3)) != 0, "nodejs identifier should be set");
}

static void test_structured_data_copy_to_with_prefix(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--structured-data-copy-to=/tmp/test"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "structured-data-copy-to with -- should parse successfully");
    ASSERT(args.copy_to_arg != NULL, "copy_to_arg should not be NULL");
    ASSERT(strcmp(args.copy_to_arg, "/tmp/test") == 0, "copy_to_arg should match provided path");
}

static void test_structured_data_copy_to_without_prefix(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "structured-data-copy-to=/tmp/test"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "structured-data-copy-to without -- should parse successfully");
    ASSERT(args.copy_to_arg != NULL, "copy_to_arg should not be NULL");
    ASSERT(strcmp(args.copy_to_arg, "/tmp/test") == 0, "copy_to_arg should match provided path");
}

static void test_structured_data_copy_to_empty(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--structured-data-copy-to="};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc != 0, "empty structured-data-copy-to should fail");
}

static void test_root_argument(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "/some/path"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "root argument should parse successfully");
    ASSERT(strcmp(args.root_arg, "/some/path") == 0, "root_arg should match provided path");
}

static void test_multiple_flags(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--verbose", "--no-content-analysis", "--no-path-refactor", "--sanitize-underscores"};
    int argc = 5;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "multiple flags should parse successfully");
    ASSERT(args.verbose == true, "verbose should be true");
    ASSERT(args.enable_content == false, "content should be disabled");
    ASSERT(args.enable_refactor == false, "refactor should be disabled");
    ASSERT(args.enable_sanitize == true, "sanitize should be enabled");
}

static void test_all_options_combined(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "/root/path", "--verbose", "--no-content-analysis", 
                    "--identifiers=composer,symfony", "--structured-data-copy-to=/dest/path"};
    int argc = 6;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "all options combined should parse successfully");
    ASSERT(strcmp(args.root_arg, "/root/path") == 0, "root should be set");
    ASSERT(args.verbose == true, "verbose should be true");
    ASSERT(args.enable_content == false, "content should be disabled");
    ASSERT((args.ident_mask & (1u<<0)) != 0, "composer should be set");
    ASSERT((args.ident_mask & (1u<<1)) != 0, "symfony should be set");
    ASSERT(strcmp(args.copy_to_arg, "/dest/path") == 0, "copy_to should be set");
}

static void test_unknown_flag(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", "--unknown-flag"};
    int argc = 2;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc != 0, "unknown flag should fail to parse");
}

static void test_root_with_all_flags(void) {
    ParsedArgs args;
    char *argv[] = {"forensic", ".", "--verbose", "--no-content-analysis", 
                    "--no-path-refactor", "--sanitize-underscores",
                    "--identifiers=drupal,node", "--structured-data-copy-to=./copy"};
    int argc = 8;
    
    int rc = parse_args(argc, argv, &args);
    ASSERT(rc == 0, "root with all flags should parse successfully");
    ASSERT(strcmp(args.root_arg, ".") == 0, "root should be '.'");
    ASSERT(args.verbose == true, "verbose should be true");
    ASSERT(args.enable_content == false, "content should be disabled");
    ASSERT(args.enable_refactor == false, "refactor should be disabled");
    ASSERT(args.enable_sanitize == true, "sanitize should be enabled");
    ASSERT((args.ident_mask & (1u<<2)) != 0, "drupal should be set");
    ASSERT((args.ident_mask & (1u<<3)) != 0, "node should be set");
    ASSERT(strcmp(args.copy_to_arg, "./copy") == 0, "copy_to should be set");
}

int main(void) {
    printf("Running command-line argument parsing tests...\n\n");
    
    test_default_args();
    test_verbose_flag();
    test_no_content_analysis();
    test_no_path_refactor();
    test_sanitize_underscores();
    test_identifiers_single();
    test_identifiers_multiple();
    test_identifiers_node_variants();
    test_structured_data_copy_to_with_prefix();
    test_structured_data_copy_to_without_prefix();
    test_structured_data_copy_to_empty();
    test_root_argument();
    test_multiple_flags();
    test_all_options_combined();
    test_unknown_flag();
    test_root_with_all_flags();
    
    printf("\n=== Test Summary ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    
    if(tests_failed == 0) {
        printf("\n✓ All tests passed!\n");
        return 0;
    } else {
        printf("\n✗ Some tests failed!\n");
        return 1;
    }
}

