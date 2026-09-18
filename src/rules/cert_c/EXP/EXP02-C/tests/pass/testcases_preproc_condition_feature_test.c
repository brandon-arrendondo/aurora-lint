/*
 * Rule: EXP02-C
 * Source: task 1264, real shapes from mbedtls library/common.h:236/252/267
 *   (MBEDTLS_HAS_BUILTIN) and valkey src/config.h:388 (__has_attribute)
 * Status: PASS - Should NOT trigger EXP02-C violation
 *
 * The condition of a `#if`/`#elif` is evaluated by the preprocessor at
 * translation time. There is no runtime evaluation to short-circuit, so a
 * call there cannot be a skipped side effect -- it is a feature test, which
 * is the only way these are ever written. Flagging one names a construct
 * that is not present (ADR-0005 misfire).
 */
#define MBEDTLS_HAS_BUILTIN(x) 0

#if defined(COMPILER_IS_GCC) && MBEDTLS_HAS_BUILTIN(__builtin_constant_p)
int gcc_builtin_path;
#endif

#if defined(__x86_64__) && defined(__has_attribute) && __has_attribute(target)
int simd_path;
#endif

#if defined(FEATURE_A) && HAS_CAPABILITY(thing)
int cap_path;
#elif defined(FEATURE_B) && HAS_CAPABILITY(other)
int other_path;
#endif
