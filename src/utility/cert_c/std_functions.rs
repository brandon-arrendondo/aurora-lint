/// Check if a function name is a known standard library function.
///
/// Covers C11 standard library, a POSIX subset, and Windows socket basics.
/// Used by DCL31-C and DCL07-C to avoid false positives on standard function
/// calls where tree-sitter cannot follow `#include` directives to verify
/// that the function was declared via a header.
pub fn is_known_standard_function(name: &str) -> bool {
    match name {
        // ===== C11 Standard Library =====

        // stdio.h
        "printf" | "fprintf" | "sprintf" | "snprintf" | "vprintf" | "vfprintf" | "vsprintf"
        | "vsnprintf" | "scanf" | "fscanf" | "sscanf" | "vscanf" | "vfscanf" | "vsscanf"
        | "fopen" | "fclose" | "fflush" | "freopen" | "fread" | "fwrite" | "fgetc" | "fgets"
        | "fputc" | "fputs" | "getc" | "getchar" | "gets" | "putc" | "putchar" | "puts"
        | "ungetc" | "fseek" | "ftell" | "rewind" | "fgetpos" | "fsetpos" | "clearerr"
        | "feof" | "ferror" | "perror" | "tmpfile" | "tmpnam" | "remove" | "rename"
        | "setbuf" | "setvbuf" => true,

        // stdlib.h
        "malloc" | "calloc" | "realloc" | "free" | "aligned_alloc" | "atoi" | "atol"
        | "atoll" | "atof" | "strtol" | "strtoll" | "strtoul" | "strtoull" | "strtof"
        | "strtod" | "strtold" | "rand" | "srand" | "abort" | "exit" | "_Exit"
        | "quick_exit" | "atexit" | "at_quick_exit" | "system" | "getenv" | "bsearch"
        | "qsort" | "abs" | "labs" | "llabs" | "div" | "ldiv" | "lldiv" | "mblen"
        | "mbtowc" | "wctomb" | "mbstowcs" | "wcstombs" => true,

        // string.h
        "memcpy" | "memmove" | "memset" | "memcmp" | "memchr" | "strcpy" | "strncpy"
        | "strcat" | "strncat" | "strcmp" | "strncmp" | "strchr" | "strrchr" | "strstr"
        | "strtok" | "strlen" | "strerror" | "strcoll" | "strxfrm" | "strpbrk" | "strspn"
        | "strcspn" => true,

        // POSIX string extensions (string.h / strings.h under _POSIX_C_SOURCE)
        "strdup" | "strndup" | "stpcpy" | "stpncpy"
        | "strcasecmp" | "strncasecmp"
        | "strtok_r" | "strerror_l" => true,

        // math.h
        "acos" | "asin" | "atan" | "atan2" | "cos" | "sin" | "tan" | "acosh" | "asinh"
        | "atanh" | "cosh" | "sinh" | "tanh" | "exp" | "exp2" | "expm1" | "frexp" | "ldexp"
        | "log" | "log2" | "log10" | "log1p" | "logb" | "ilogb" | "modf" | "scalbn"
        | "scalbln" | "pow" | "sqrt" | "cbrt" | "hypot" | "fabs" | "fmod" | "remainder"
        | "remquo" | "fma" | "fmax" | "fmin" | "fdim" | "nan" | "ceil" | "floor" | "trunc"
        | "round" | "lround" | "llround" | "nearbyint" | "rint" | "lrint" | "llrint"
        | "copysign" | "nextafter" | "nexttoward" | "isnan" | "isinf" | "isfinite"
        | "isnormal" | "signbit" | "isgreater" | "isgreaterequal" | "isless" | "islessequal"
        | "islessgreater" | "isunordered"
        // float variants
        | "acosf" | "asinf" | "atanf" | "atan2f" | "cosf" | "sinf" | "tanf" | "acoshf"
        | "asinhf" | "atanhf" | "coshf" | "sinhf" | "tanhf" | "expf" | "exp2f" | "expm1f"
        | "frexpf" | "ldexpf" | "logf" | "log2f" | "log10f" | "log1pf" | "logbf" | "ilogbf"
        | "modff" | "scalbnf" | "scalblnf" | "powf" | "sqrtf" | "cbrtf" | "hypotf" | "fabsf"
        | "fmodf" | "remainderf" | "remquof" | "fmaf" | "fmaxf" | "fminf" | "fdimf" | "nanf"
        | "ceilf" | "floorf" | "truncf" | "roundf" | "lroundf" | "llroundf" | "nearbyintf"
        | "rintf" | "lrintf" | "llrintf" | "copysignf" | "nextafterf" | "nexttowardf"
        // long double variants
        | "acosl" | "asinl" | "atanl" | "atan2l" | "cosl" | "sinl" | "tanl" | "acoshl"
        | "asinhl" | "atanhl" | "coshl" | "sinhl" | "tanhl" | "expl" | "exp2l" | "expm1l"
        | "frexpl" | "ldexpl" | "logl" | "log2l" | "log10l" | "log1pl" | "logbl" | "ilogbl"
        | "modfl" | "scalbnl" | "scalblnl" | "powl" | "sqrtl" | "cbrtl" | "hypotl" | "fabsl"
        | "fmodl" | "remainderl" | "remquol" | "fmal" | "fmaxl" | "fminl" | "fdiml" | "nanl"
        | "ceill" | "floorl" | "truncl" | "roundl" | "lroundl" | "llroundl" | "nearbyintl"
        | "rintl" | "lrintl" | "llrintl" | "copysignl" | "nextafterl" | "nexttowardl" => true,

        // ctype.h
        "isalnum" | "isalpha" | "isblank" | "iscntrl" | "isdigit" | "isgraph" | "islower"
        | "isprint" | "ispunct" | "isspace" | "isupper" | "isxdigit" | "tolower"
        | "toupper" => true,

        // wctype.h
        "iswalnum" | "iswalpha" | "iswblank" | "iswcntrl" | "iswdigit" | "iswgraph"
        | "iswlower" | "iswprint" | "iswpunct" | "iswspace" | "iswupper" | "iswxdigit"
        | "towlower" | "towupper" | "iswctype" | "wctype" | "towctrans" | "wctrans" => true,

        // wchar.h
        "wprintf" | "fwprintf" | "swprintf" | "vwprintf" | "vfwprintf" | "vswprintf"
        | "wscanf" | "fwscanf" | "swscanf" | "vwscanf" | "vfwscanf" | "vswscanf" | "fgetwc"
        | "fgetws" | "fputwc" | "fputws" | "getwc" | "getwchar" | "putwc" | "putwchar"
        | "ungetwc" | "wcstol" | "wcstoll" | "wcstoul" | "wcstoull" | "wcstof" | "wcstod"
        | "wcstold" | "wcscpy" | "wcsncpy" | "wcscat" | "wcsncat" | "wcscmp" | "wcsncmp"
        | "wcschr" | "wcsrchr" | "wcsstr" | "wcstok" | "wcslen" | "wmemcpy" | "wmemmove"
        | "wmemset" | "wmemcmp" | "wmemchr" | "wcscoll" | "wcsxfrm" | "wcspbrk" | "wcsspn"
        | "wcscspn" | "wcsftime" | "btowc" | "wctob" | "mbsinit" | "mbrlen" | "mbrtowc"
        | "wcrtomb" | "mbsrtowcs" | "wcsrtombs" => true,

        // time.h
        "time" | "difftime" | "mktime" | "strftime" | "gmtime" | "localtime" | "asctime"
        | "ctime" | "clock" | "timespec_get" => true,

        // signal.h
        "signal" | "raise" => true,

        // setjmp.h
        "setjmp" | "longjmp" => true,

        // locale.h
        "setlocale" | "localeconv" => true,

        // assert.h
        "assert" => true,

        // stdarg.h (macros, but sometimes seen as function calls)
        "va_start" | "va_end" | "va_arg" | "va_copy" => true,

        // inttypes.h
        "imaxabs" | "imaxdiv" | "strtoimax" | "strtoumax" | "wcstoimax" | "wcstoumax" => true,

        // fenv.h
        "feclearexcept" | "fegetexceptflag" | "feraiseexcept" | "fesetexceptflag"
        | "fetestexcept" | "fegetround" | "fesetround" | "fegetenv" | "feholdexcept"
        | "fesetenv" | "feupdateenv" => true,

        // complex.h
        "cabs" | "cabsf" | "cabsl" | "cacos" | "cacosf" | "cacosl" | "cacosh" | "cacoshf"
        | "cacoshl" | "carg" | "cargf" | "cargl" | "casin" | "casinf" | "casinl" | "casinh"
        | "casinhf" | "casinhl" | "catan" | "catanf" | "catanl" | "catanh" | "catanhf"
        | "catanhl" | "ccos" | "ccosf" | "ccosl" | "ccosh" | "ccoshf" | "ccoshl" | "cexp"
        | "cexpf" | "cexpl" | "cimag" | "cimagf" | "cimagl" | "clog" | "clogf" | "clogl"
        | "conj" | "conjf" | "conjl" | "cpow" | "cpowf" | "cpowl" | "cproj" | "cprojf"
        | "cprojl" | "creal" | "crealf" | "creall" | "csin" | "csinf" | "csinl" | "csinh"
        | "csinhf" | "csinhl" | "csqrt" | "csqrtf" | "csqrtl" | "ctan" | "ctanf" | "ctanl"
        | "ctanh" | "ctanhf" | "ctanhl" => true,

        // ===== POSIX Subset =====

        // unistd.h
        "read" | "write" | "close" | "fork" | "execl" | "execle" | "execlp" | "execv"
        | "execve" | "execvp" | "pipe" | "dup" | "dup2" | "sleep" | "usleep" | "getpid"
        | "getppid" | "getuid" | "geteuid" | "getgid" | "getegid" | "access" | "chdir"
        | "getcwd" | "chown" | "link" | "unlink" | "rmdir" | "symlink" | "readlink"
        | "isatty" | "lseek" | "sysconf" | "pathconf" | "fpathconf" | "alarm" | "pause"
        | "setsid" | "setpgid" | "getpgid" | "tcgetpgrp" | "tcsetpgrp" | "fsync"
        | "fdatasync" | "truncate" | "ftruncate" | "nice" => true,

        // sys/socket.h
        "socket" | "bind" | "listen" | "accept" | "connect" | "send" | "recv" | "sendto"
        | "recvfrom" | "sendmsg" | "recvmsg" | "shutdown" | "setsockopt" | "getsockopt"
        | "getpeername" | "getsockname" | "socketpair" => true,

        // arpa/inet.h
        "htons" | "htonl" | "ntohs" | "ntohl" | "inet_addr" | "inet_ntoa" | "inet_pton"
        | "inet_ntop" => true,

        // netdb.h
        "getaddrinfo" | "freeaddrinfo" | "gai_strerror" | "getnameinfo" | "getservbyname"
        | "getservbyport" | "gethostbyname" | "gethostbyaddr" => true,

        // pthread basics
        "pthread_create" | "pthread_join" | "pthread_detach" | "pthread_exit" | "pthread_self"
        | "pthread_equal" | "pthread_cancel" | "pthread_mutex_init" | "pthread_mutex_destroy"
        | "pthread_mutex_lock" | "pthread_mutex_trylock" | "pthread_mutex_unlock"
        | "pthread_cond_init" | "pthread_cond_destroy" | "pthread_cond_wait"
        | "pthread_cond_signal" | "pthread_cond_broadcast" | "pthread_cond_timedwait"
        | "pthread_rwlock_init" | "pthread_rwlock_destroy" | "pthread_rwlock_rdlock"
        | "pthread_rwlock_wrlock" | "pthread_rwlock_unlock" | "pthread_key_create"
        | "pthread_key_delete" | "pthread_getspecific" | "pthread_setspecific"
        | "pthread_once" | "pthread_attr_init" | "pthread_attr_destroy" => true,

        // fcntl / stat / mmap
        "open" | "creat" | "fcntl" | "stat" | "fstat" | "lstat" | "mkdir" | "chmod"
        | "fchmod" | "umask" | "mmap" | "munmap" | "mprotect" | "msync" | "mlock"
        | "munlock" => true,

        // select / poll / epoll
        "select" | "pselect" | "poll" | "ppoll" | "epoll_create" | "epoll_create1"
        | "epoll_ctl" | "epoll_wait" => true,

        // POSIX misc
        "opendir" | "readdir" | "closedir" | "rewinddir" | "seekdir" | "telldir"
        | "dlopen" | "dlclose" | "dlsym" | "dlerror" | "getopt" | "getopt_long"
        | "strsignal" | "strerror_r" | "realpath" | "mkstemp" | "mkdtemp" | "glob"
        | "globfree" | "regcomp" | "regexec" | "regfree" | "regerror" => true,

        // ===== Windows Socket Basics =====
        "WSAStartup" | "WSACleanup" | "WSAGetLastError" | "WSASetLastError"
        | "closesocket" | "ioctlsocket" | "WSASocketA" | "WSASocketW"
        | "WSASend" | "WSARecv" => true,

        // ===== Windows API (WinAPI / Win32) =====

        // Handle management
        "CloseHandle" | "DuplicateHandle" | "GetCurrentProcess" | "GetCurrentThread"
        | "OpenProcess" | "OpenThread" => true,

        // Windows Crypto API (wincrypt.h)
        "CryptAcquireContext" | "CryptReleaseContext"
        | "CryptCreateHash" | "CryptDestroyHash" | "CryptHashData" | "CryptGetHashParam"
        | "CryptDeriveKey" | "CryptDestroyKey" | "CryptGenKey"
        | "CryptSetKeyParam" | "CryptGetKeyParam"
        | "CryptEncrypt" | "CryptDecrypt"
        | "CryptGenRandom" | "CryptImportKey" | "CryptExportKey"
        | "CryptSignHash" | "CryptVerifySignature"
        | "CryptStringToBinaryA" | "CryptStringToBinaryW"
        | "CryptBinaryToStringA" | "CryptBinaryToStringW" => true,

        // Windows Authentication
        "LogonUserA" | "LogonUserW" | "LogonUser"
        | "ImpersonateLoggedOnUser" | "RevertToSelf"
        | "LookupAccountNameA" | "LookupAccountNameW"
        | "OpenProcessToken" | "GetTokenInformation" => true,

        // Windows memory
        "SecureZeroMemory" | "ZeroMemory" | "FillMemory" | "CopyMemory" | "MoveMemory"
        | "HeapAlloc" | "HeapFree" | "HeapReAlloc" | "HeapCreate" | "HeapDestroy"
        | "LocalAlloc" | "LocalFree" | "LocalReAlloc"
        | "GlobalAlloc" | "GlobalFree" | "GlobalReAlloc" | "GlobalLock" | "GlobalUnlock"
        | "VirtualAlloc" | "VirtualFree" | "VirtualLock" | "VirtualUnlock"
        | "VirtualProtect" | "VirtualQuery" => true,

        // Windows file I/O
        "CreateFileA" | "CreateFileW" | "CreateFile"
        | "ReadFile" | "WriteFile" | "SetFilePointer" | "SetFilePointerEx"
        | "GetFileSize" | "GetFileSizeEx" | "SetEndOfFile"
        | "FlushFileBuffers" | "GetFileTime" | "SetFileTime" | "CompareFileTime"
        | "DeleteFileA" | "DeleteFileW" | "MoveFileA" | "MoveFileW" | "CopyFileA" | "CopyFileW"
        | "GetTempFileNameA" | "GetTempFileNameW" | "GetTempPathA" | "GetTempPathW"
        | "GetCurrentDirectoryA" | "GetCurrentDirectoryW"
        | "SetCurrentDirectoryA" | "SetCurrentDirectoryW"
        | "CreateDirectoryA" | "CreateDirectoryW" | "RemoveDirectoryA" | "RemoveDirectoryW"
        | "FindFirstFileA" | "FindFirstFileW" | "FindNextFileA" | "FindNextFileW"
        | "FindClose" => true,

        // Windows process and thread
        "CreateProcessA" | "CreateProcessW" | "CreateProcess"
        | "CreateProcessAsUserA" | "CreateProcessAsUserW" | "CreateProcessAsUser"
        | "TerminateProcess" | "ExitProcess"
        | "CreateThread" | "ExitThread" | "TerminateThread"
        | "WaitForSingleObject" | "WaitForMultipleObjects"
        | "GetExitCodeProcess" | "GetExitCodeThread"
        | "GetCurrentProcessId" | "GetCurrentThreadId"
        | "SuspendThread" | "ResumeThread" => true,

        // Windows synchronization
        "CreateMutex" | "CreateMutexA" | "CreateMutexW"
        | "OpenMutex" | "OpenMutexA" | "OpenMutexW"
        | "ReleaseMutex" | "WaitForSingleObjectEx"
        | "CreateEvent" | "CreateEventA" | "CreateEventW"
        | "SetEvent" | "ResetEvent" | "PulseEvent"
        | "CreateSemaphore" | "CreateSemaphoreA" | "CreateSemaphoreW"
        | "ReleaseSemaphore"
        | "InitializeCriticalSection" | "DeleteCriticalSection"
        | "EnterCriticalSection" | "LeaveCriticalSection" => true,

        // Windows DLL/library
        "LoadLibraryA" | "LoadLibraryW" | "LoadLibrary"
        | "FreeLibrary" | "GetProcAddress"
        | "GetModuleHandleA" | "GetModuleHandleW" | "GetModuleHandle" => true,

        // Windows registry
        "RegOpenKeyExA" | "RegOpenKeyExW" | "RegOpenKeyEx"
        | "RegCreateKeyA" | "RegCreateKeyW" | "RegCreateKeyExA" | "RegCreateKeyExW"
        | "RegCloseKey" | "RegDeleteKeyA" | "RegDeleteKeyW"
        | "RegQueryValueExA" | "RegQueryValueExW" | "RegQueryValueEx"
        | "RegSetValueExA" | "RegSetValueExW" | "RegSetValueEx"
        | "RegEnumKeyExA" | "RegEnumKeyExW" | "RegEnumValueA" | "RegEnumValueW"
        | "SHRegOpenUSKeyA" | "SHRegOpenUSKeyW" => true,

        // Windows IPC (pipes, mailslots)
        "CreateNamedPipeA" | "CreateNamedPipeW" | "CreateNamedPipe"
        | "ConnectNamedPipe" | "DisconnectNamedPipe"
        | "CreatePipe" | "CallNamedPipeA" | "CallNamedPipeW" => true,

        // Windows networking
        "NetUserChangePassword" | "NetUserSetInfo" | "NetUserGetInfo"
        | "NetApiBufferFree" => true,

        // Windows error handling
        "GetLastError" | "SetLastError" | "FormatMessageA" | "FormatMessageW" => true,

        // Windows time
        "GetSystemTime" | "GetLocalTime" | "SystemTimeToFileTime" | "FileTimeToSystemTime"
        | "GetSystemTimeAsFileTime" => true,

        // Windows system info
        "SetComputerNameA" | "SetComputerNameW"
        | "GetComputerNameA" | "GetComputerNameW"
        | "GetSystemInfo" | "GetVersionEx" | "GetVersion" => true,

        // Windows path utilities (shlwapi.h)
        "PathAppendA" | "PathAppendW" | "PathAppend"
        | "PathCombineA" | "PathCombineW"
        | "PathFileExistsA" | "PathFileExistsW"
        | "PathFindFileNameA" | "PathFindFileNameW" => true,

        // Windows GDI (graphics)
        "DeleteObject" | "SelectObject" | "ReleaseDC" | "GetDC"
        | "GetDesktopWindow" | "GetClientRect"
        | "CreateCompatibleDC" | "CreateCompatibleBitmap"
        | "GetDIBits" | "GetObject" | "BitBlt"
        | "CreateDIBSection" | "GetDeviceCaps" => true,

        // Windows desktop/station (window station objects)
        "CreateWindowStationA" | "CreateWindowStationW"
        | "CloseWindowStation" | "OpenWindowStationA" | "OpenWindowStationW"
        | "CreateDesktopA" | "CreateDesktopW"
        | "CloseDesktop" | "OpenDesktopA" | "OpenDesktopW" => true,

        // ===== Uppercase Macro Wrappers =====
        // Some codebases use uppercase macros that expand to standard functions.
        // Tree-sitter sees them as calls to these uppercase names.
        "ALLOCA" | "SNPRINTF" | "VSNPRINTF"
        | "GETENV" | "PUTENV" | "SYSTEM"
        | "POPEN" | "PCLOSE"
        | "OPEN" | "CLOSE" | "READ" | "WRITE"
        | "EXECL" | "EXECLP" | "EXECV" | "EXECVP" | "EXECLE" | "EXECVE"
        | "SLEEP" | "USLEEP"
        | "STAT" | "FSTAT" | "LSTAT"
        | "ACCESS" | "MKDIR" | "RMDIR" | "UNLINK" | "RENAME"
        | "MKTEMP" | "TMPNAM" | "TEMPNAM"
        | "FOPEN" | "FDOPEN" | "FREOPEN"
        | "CHMOD" | "CHOWN" | "CHDIR" => true,

        _ => false,
    }
}

/// Returns true if the given function is known to return values that can span
/// the full range of an integer type, making `func() + small_literal` a
/// potential overflow/wrap risk.
///
/// Used by INT32-C and INT30-C to refine the opaque-call suppression heuristic:
/// `strlen(buf) + 1` remains suppressed, but `atoi(buf) + 1` is flagged.
pub fn is_full_range_return_function(name: &str) -> bool {
    matches!(
        name,
        // String-to-integer parsers: return arbitrary user-supplied values
        "atoi" | "atol" | "atoll"
        | "strtol" | "strtoul" | "strtoll" | "strtoull"
        | "strtoimax" | "strtoumax"
        // Wide-char string-to-integer parsers
        | "wcstol" | "wcstoul" | "wcstoll" | "wcstoull"
        | "wcstoimax" | "wcstoumax"
        // Random number generators: values can reach INT_MAX / RAND_MAX
        | "rand" | "random" | "lrand48" | "mrand48" | "rand_r"
        // Juliet-specific macro (expands to rand())
        | "RAND32"
        // Network byte order (can return full 32-bit range)
        | "ntohl" | "ntohs"
    )
}

/// Returns true if the function decodes an integer from an untrusted/stored
/// byte stream — a serialized length, count, or offset whose value an attacker
/// can influence. Distinct from [`is_full_range_return_function`] (which covers
/// generic libc parsers/RNG): this is the deserialization category that the
/// SQLite real-world audit flagged as the dominant true-positive *and*
/// false-negative source ("untrusted length/count from varint / column-bytes /
/// page bytes drives a read or arithmetic without a bound check"). Recognizing
/// these as risky sources lets the INT32-C provenance gate keep firing on the
/// genuine decode-path overflows while still suppressing bounded local
/// counters.
///
/// The names span varint decoders, fixed-width byte-buffer integer readers, and
/// stored-value accessors — patterns common to serialization-heavy C
/// (SQLite, protobuf-style codecs, on-disk/wire formats).
pub fn is_untrusted_decode_function(name: &str) -> bool {
    matches!(
        name,
        // Varint decoders (return/yield attacker-controlled integers)
        "getVarint" | "getVarint32"
        | "sqlite3GetVarint" | "sqlite3GetVarint32"
        | "sqlite3Fts3GetVarint" | "sqlite3Fts3GetVarint32" | "sqlite3Fts3GetVarintU"
        | "fts3GetVarint" | "fts3GetVarint32"
        | "sqlite3Fts5GetVarint" | "fts5GetVarint"
        | "sessionVarintGet"
        // Fixed-width integer reads from an untrusted byte buffer
        | "get2byte" | "get4byte" | "sqlite3Get4byte" | "sqlite3Get2byte"
        // Stored-value accessors: lengths/ints from DB rows the caller does not control
        | "sqlite3_value_int" | "sqlite3_value_int64"
        | "sqlite3_value_bytes" | "sqlite3_value_bytes16"
        | "sqlite3_column_int" | "sqlite3_column_int64"
        | "sqlite3_column_bytes" | "sqlite3_column_bytes16"
    )
}
