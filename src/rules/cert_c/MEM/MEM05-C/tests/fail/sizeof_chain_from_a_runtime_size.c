/*
 * Rule: MEM05-C
 * Source: custom
 * Status: FAIL - Should trigger MEM05-C violation
 * Description: A chain of 20 arrays, each sized by sizeof of the one before
 * twice, from a runtime-sized first array: every link is a VLA. Reading each
 * operand's size anew at every reference doubles the work per link, so the
 * chain also bounds the rule's time.
 */
void runtime_chain(int n) {
    char a0[n];
    char a1[sizeof a0 + sizeof a0];
    char a2[sizeof a1 + sizeof a1];
    char a3[sizeof a2 + sizeof a2];
    char a4[sizeof a3 + sizeof a3];
    char a5[sizeof a4 + sizeof a4];
    char a6[sizeof a5 + sizeof a5];
    char a7[sizeof a6 + sizeof a6];
    char a8[sizeof a7 + sizeof a7];
    char a9[sizeof a8 + sizeof a8];
    char a10[sizeof a9 + sizeof a9];
    char a11[sizeof a10 + sizeof a10];
    char a12[sizeof a11 + sizeof a11];
    char a13[sizeof a12 + sizeof a12];
    char a14[sizeof a13 + sizeof a13];
    char a15[sizeof a14 + sizeof a14];
    char a16[sizeof a15 + sizeof a15];
    char a17[sizeof a16 + sizeof a16];
    char a18[sizeof a17 + sizeof a17];
    char a19[sizeof a18 + sizeof a18];
    char a20[sizeof a19 + sizeof a19];
    (void)a20;
}
