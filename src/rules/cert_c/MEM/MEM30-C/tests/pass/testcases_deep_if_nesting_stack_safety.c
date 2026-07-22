/*
 * Rule: MEM30-C
 * Source: task 295 (explicit-stack conversion) regression
 * Status: PASS - No MEM30-C violation
 * Reason: deep sequential if-nesting (2000 levels), safe
 * free/no-reuse pattern in the innermost block. Exists to prove the
 * frame-stack conversion of MemoryAnalyzer::analyze_function_body/
 * analyze_if_statement (and the related GlobalTracker::scan_function_body
 * and MemoryAnalyzer::unconditionally_diverges conversions) does not
 * recurse per nesting level (would overflow the native call stack well
 * before this depth in the pre-task-295 implementation).
 */

#include <stdlib.h>

int main() {
    int x = 1;
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
    if (x) {
        int *p = malloc(sizeof(int));
        if (p == NULL) { return -1; }
        *p = 42;
        free(p);
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    }
    return 0;
}
