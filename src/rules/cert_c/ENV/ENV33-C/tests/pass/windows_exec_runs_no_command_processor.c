/*
 * Rule: ENV33-C
 * Source: regression
 * Status: PASS under the default and strict presets; VIOLATION under pedantic
 * Expect: default=clean strict=clean pedantic=violation
 *
 * _execl and _spawnl run a program directly, without a command processor, the
 * way CERT's compliant execve() and CreateProcess() solutions do
 * (env33_exec_spawn_exempt). The pedantic policy reports them like system().
 */

#include <process.h>
#include <stddef.h>

void run_listing(void) {
  _execl("C:\\Windows\\System32\\where.exe", "where.exe", "notepad", NULL);
}

void spawn_listing(void) {
  _spawnl(_P_WAIT, "C:\\Windows\\System32\\where.exe", "where.exe", "notepad", NULL);
}
