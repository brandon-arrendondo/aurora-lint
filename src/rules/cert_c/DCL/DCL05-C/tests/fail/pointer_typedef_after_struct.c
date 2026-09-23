/*
 * Rule: DCL05-C
 * Source: real-world (ventoy process.h PSYSTEM_HANDLE_INFORMATION_EX etc.,
 *         labelled TP)
 * Status: FAIL - Should trigger DCL05-C violation
 *
 * The Windows idiom of declaring the struct and a pointer alias in one
 * typedef: the second declarator hides a pointer and must keep firing even
 * though the first (the struct itself) is compliant.
 */

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    unsigned long NumberOfHandles;
    unsigned long Reserved;
    void *Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX, *PSYSTEM_HANDLE_INFORMATION_EX;
