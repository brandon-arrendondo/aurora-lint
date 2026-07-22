/*
 * Rule: MEM31-C
 * Source: task 295 (explicit-stack conversion) regression
 * Status: PASS - No MEM31-C violation
 * Reason: deep sequential if-nesting (2000 levels), memory
 * allocated and freed in the same (innermost) scope. Exists to prove
 * the frame-stack conversion of MemoryLeakAnalyzer::analyze_node/
 * analyze_if (and the related switch/loop continuation frames) does
 * not recurse per nesting level (would overflow the native call stack
 * well before this depth in the pre-task-295 implementation).
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
