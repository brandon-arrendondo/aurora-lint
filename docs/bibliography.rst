Bibliography
============

Academic papers, reports, and industry references used to benchmark SqC and
contextualize its results against the static analysis landscape.

Juliet & Vulnerability Detection Studies
-----------------------------------------

**[ISSTA2022]** Steinhöfel, D. et al.
"An Empirical Study on the Effectiveness of Static C Code Analyzers for
Vulnerability Detection."
*ISSTA 2022*, ACM SIGSOFT International Symposium on Software Testing and
Analysis.

| ACM: https://dl.acm.org/doi/10.1145/3533767.3534380
| Preprint: https://mediatum.ub.tum.de/doc/1659728/1659728.pdf

Key finding: state-of-the-art tools miss 47--80% of vulnerabilities; on
average ~20% detection. Combining tools increases effectiveness by 26%.

----

**[Goseva2015]** Goseva-Popstojanova, K. and Perhinschi, A.
"On the capability of static code analysis to detect security
vulnerabilities."
*Information and Software Technology*, 2015.

| PDF: https://community.wvu.edu/~kagoseva/Papers/IST-2015.pdf
| ACM: https://dl.acm.org/doi/10.1016/j.infsof.2015.08.002

Key finding: 27% of C/C++ vulnerabilities missed by all three commercial
tools tested; 41% detected by all three. Even commercial tools miss
significant portions.

----

**[JKU2014]** Neumayer, P. et al.
"Using the Juliet Test Suite to Compare Static Security Scanners."
Johannes Kepler University Linz, 2014.

| PDF: https://www.se.jku.at/wp-content/uploads/2014/08/2014.Using-the-Juliet-Test-Suite.pdf

Directly compares scanner performance using the Juliet Test Suite as ground
truth.

----

**[Li2024]** Li, K. et al.
"An Empirical Study of Static Analysis Tools for Secure Code Review."
*ISSTA 2024*, ACM.

| ACM: https://dl.acm.org/doi/10.1145/3650212.3680313
| Preprint: https://arxiv.org/abs/2407.12241

Key finding: 52% of vulnerable code changes warned by a single tool; 76%+
of warnings in vulnerable functions are irrelevant to the actual
vulnerability; 22% of VCCs undetected by any tool.

----

**[Chen2023]** Chen, Y. et al.
"A Comparison of Static Analysis Tools for Vulnerability Detection in
C/C++ Code."

Compares multiple tools on C/C++ vulnerability detection with quantitative
precision/recall metrics.

NIST SATE Reports
-----------------

**[SATE-VI]** National Institute of Standards and Technology.
"Static Analysis Tool Exposition (SATE) VI."
NIST, 2018--2023.

| Overview: https://www.nist.gov/itl/ssd/software-quality-group/static-analysis-tool-exposition-sate-vi
| Bug Injection Report: https://www.nist.gov/publications/sate-vi-report-bug-injection-and-collection
| Ockham Criteria: https://www.nist.gov/publications/sate-vi-ockham-sound-analysis-criteria-0
| Workshop: https://samate.nist.gov/SATE6Workshop.html

Security-focused bug-finding evaluation exercise. Showed significant
variability across tool effectiveness depending on test cases, bug classes,
and complexity.

----

**[NIST-SP500-297]** Okun, V. et al.
"Report on the Static Analysis Tool Exposition (SATE) IV."
NIST SP 500-297.

| PDF: https://www.govinfo.gov/content/pkg/GOVPUB-C13-85ce8522f8e17f9964cecdf57250a8c6/pdf/GOVPUB-C13-85ce8522f8e17f9964cecdf57250a8c6.pdf

----

**[Juliet-v1.3]** NIST SAMATE.
"Juliet Test Suite v1.3 for C/C++."

| Download: https://samate.nist.gov/SARD/test-suites/112

54,484 C/C++ files covering 118 CWEs with ground truth (OMITBAD/OMITGOOD).

Tool Comparison & Industry Studies
----------------------------------

**[Lenarduzzi2022]** Lenarduzzi, V., Pecorelli, F., Saarimäki, N., Lujan, S.,
and Palomba, F.
"A critical comparison on six static analysis tools: Detection, agreement,
and precision."
*Journal of Systems and Software*, 2022.

| arXiv: https://arxiv.org/abs/2101.08832
| ScienceDirect: https://www.sciencedirect.com/science/article/pii/S0164121222002515

Compared six tools (Java); FindBugs 57% precision. Low inter-tool agreement
across all pairs.

----

**[Chou2005]** Chou, A. et al.
"False Positives Over Time (Coverity)."
Bug Workshop 2005.

| PDF: https://www.cs.umd.edu/~pugh/BugWorkshop05/papers/34-chou.pdf

Early industry data on FP rates and how they evolve as tools mature.

----

**[Machiry2022]** Machiry, A. et al.
"An Empirical Study on the Use of Static Analysis Tools."

| PDF: https://machiry.github.io/files/emsast.pdf

How developers use static analysis in practice; adoption barriers
including FP rates.

----

**[NCC-Group]** NCC Group.
"Best Practices for Static Analysis."

Industry guidance on deploying static analysis effectively, managing
FP rates, and integrating into development workflows.

False Positive Rate Benchmarks
------------------------------

**[CASTLE2025]** CASTLE Benchmarking Dataset. 2025.

| arXiv: https://arxiv.org/abs/2503.09433

New benchmark for static code analyzers and LLMs; considers both TP/FP +
severity weighting.

----

**[AICodeSec2025]** "2025 AI Code Security Benchmark: Snyk vs Semgrep vs
CodeQL."

| Blog: https://sanj.dev/post/ai-code-security-tools-comparison

CodeQL 5% FP, Snyk 8% FP, Semgrep 12% FP (AI-augmented SAST).

Industry FP Rate Context
~~~~~~~~~~~~~~~~~~~~~~~~~

- **10--20% FP rate**: optimally acceptable for SAST adoption in development
  (industry consensus)
- **5% FP rate**: stringent target (DeepSource, validated by major tech
  companies)
- **3--48%**: observed range across 10 SAST tools (2018 study)
- **>95% FP rate**: open-source SAST on Linux kernel null-pointer deref
  (worst case)

Standards & Specifications
--------------------------

**[CERT-C]** Software Engineering Institute.
"SEI CERT C Coding Standard."

| https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard

283 rules across 17 categories. The rule set implemented by SqC.

----

**[SARIF-2.1]** OASIS.
"Static Analysis Results Interchange Format (SARIF) Version 2.1.0."

| https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

The output format used by SqC for CI/CD integration.

NASA & Aerospace
-----------------

**[NASA-SA]** NASA.
"Static Code Analysis for Security."

Static analysis practices in safety-critical aerospace software
development.
