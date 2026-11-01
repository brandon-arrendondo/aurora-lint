Bibliography
============

Academic papers, reports, and industry references used to benchmark aurora-lint and
contextualize its results against the static analysis landscape.

Juliet & Vulnerability Detection Studies
-----------------------------------------

**[Lipp2022]** Lipp, S., Banescu, S., and Pretschner, A.
"An Empirical Study on the Effectiveness of Static C Code Analyzers for
Vulnerability Detection."
*Proc. 31st ACM SIGSOFT International Symposium on Software Testing and
Analysis (ISSTA 2022)*, pp. 544--555.

| DOI: https://doi.org/10.1145/3533767.3534380
| Preprint: https://mediatum.ub.tum.de/doc/1659728/1659728.pdf

Key finding (Section 5.1 of the preprint): even the best-performing single
analyzer misses between 47% and 80% of the benchmark's 192 real-world
vulnerabilities, depending on which of the four evaluation scenarios is
used. The best combination of analyzers still misses 30--69%, while flagging
15 percentage points more functions (Section 5.2).

----

**[Goseva2015]** Goseva-Popstojanova, K. and Perhinschi, A.
"On the capability of static code analysis to detect security
vulnerabilities."
*Information and Software Technology* 68:18--33, 2015.

| DOI: https://doi.org/10.1016/j.infsof.2015.08.002
| PDF: https://community.wvu.edu/~kagoseva/Papers/IST-2015.pdf

Key finding (abstract): 27% of C/C++ vulnerabilities were missed by all
three commercial tools tested, and 41% were detected by all three.

----

**[Wagner2014]** Wagner, A. and Sametinger, J.
"Using the Juliet Test Suite to Compare Static Security Scanners."
*Proc. 11th International Conference on Security and Cryptography
(SECRYPT 2014)*, pp. 244--252.

| DOI: https://doi.org/10.5220/0005032902440252
| PDF: https://www.se.jku.at/wp-content/uploads/2014/08/2014.Using-the-Juliet-Test-Suite.pdf

Directly compares scanner performance using the Juliet Test Suite as ground
truth.

----

**[Charoenwet2024]** Charoenwet, W., Thongtanunam, P., Pham, V.-T., and
Treude, C.
"An Empirical Study of Static Analysis Tools for Secure Code Review."
*Proc. 33rd ACM SIGSOFT International Symposium on Software Testing and
Analysis (ISSTA 2024)*, pp. 691--703.

| DOI: https://doi.org/10.1145/3650212.3680313
| Preprint: https://arxiv.org/abs/2407.12241

Key finding (abstract): a single SAST tool warns in the vulnerable functions
of 52% of vulnerability-contributing commits; at least 76% of warnings in
vulnerable functions are irrelevant to the vulnerability; 22% of VCCs remain
undetected because of limitations of the tools' rules.

----

**[Arusoaie2017]** Arusoaie, A., Ciobaca, S., Craciun, V., Gavrilut, D.,
and Lucanu, D.
"A Comparison of Open-Source Static Analysis Tools for Vulnerability
Detection in C/C++ Code."
*Proc. 19th International Symposium on Symbolic and Numeric Algorithms for
Scientific Computing (SYNASC 2017)*, IEEE, pp. 161--168.

| DOI: https://doi.org/10.1109/SYNASC.2017.00035

From the abstract: benchmarks several open-source C/C++ static analyzers
against the Toyota ITC test suite, a synthetic benchmark, by detection rate
and false-positive rate, and introduces a "robust detection" metric.

NIST SATE Reports
-----------------

**[SATE-VI]** National Institute of Standards and Technology.
"Static Analysis Tool Exposition (SATE) VI."
NIST, 2018--2023.

| Overview: https://www.nist.gov/itl/csd/secure-systems-and-applications/static-analysis-tool-exposition-sate-vi
| Bug Injection Report: Delaitre, A. et al., "SATE VI Report: Bug Injection
  and Collection," NIST SP 500-341, 2023. https://doi.org/10.6028/NIST.SP.500-341
| Ockham Criteria: Black, P. E. and Walia, K. S., "SATE VI Ockham Sound
  Analysis Criteria," NISTIR 8304, 2020. https://doi.org/10.6028/NIST.IR.8304
| Workshop: https://www.nist.gov/itl/csd/secure-systems-and-applications/static-analysis-tool-exposition-sate-vi-workshop

Security-focused bug-finding evaluation exercise. Its report finds
significant variability in tool effectiveness depending on the test cases,
bug classes, and bug complexity.

----

**[NIST-SP500-297]** Okun, V., Delaitre, A., and Black, P. E.
"Report on the Static Analysis Tool Exposition (SATE) IV."
NIST SP 500-297, January 2013.

| DOI: https://doi.org/10.6028/NIST.SP.500-297
| PDF: https://www.govinfo.gov/content/pkg/GOVPUB-C13-85ce8522f8e17f9964cecdf57250a8c6/pdf/GOVPUB-C13-85ce8522f8e17f9964cecdf57250a8c6.pdf

----

**[Juliet-v1.3]** NSA Center for Assured Software.
"Juliet C/C++ 1.3." NIST SARD test suite 112, 2017.

| Download: https://samate.nist.gov/SARD/test-suites/112

SARD's page for the suite lists 64,099 test cases organized under 118 CWEs.
That count is of test cases, not files; the file counts in
:doc:`juliet-history` are of the files aurora-lint scans, a different unit.

Tool Comparison & Industry Studies
----------------------------------

**[Lenarduzzi2022]** Lenarduzzi, V., Pecorelli, F., Saarimäki, N., Lujan, S.,
and Palomba, F.
"A critical comparison on six static analysis tools: Detection, agreement,
and precision."
*Journal of Systems and Software* 198:111575, 2023.

| DOI: https://doi.org/10.1016/j.jss.2022.111575
| arXiv: https://arxiv.org/abs/2101.08832

Compared six tools on Java projects; the abstract reports little to no
agreement among the tools and a low degree of precision (FindBugs' 57% is
the paper's own figure for that tool).

----

**[Chou2005]** Chou, A.
"False Positives Over Time: A Problem in Deploying Static Analysis Tools."
Bug Workshop 2005.

| PDF: https://www.cs.umd.edu/~pugh/BugWorkshop05/papers/34-chou.pdf

A one-page workshop abstract on mitigating false positives: they
accumulate over time because developers fix the real defects and leave the
false positives in the code. It tabulates mitigation techniques and adds
observations from Coverity customers. It gives no FP rates.

----

**[Shen2025]** Shen, M., Pillai, A. A., Yuan, B. A., Davis, J. C., and
Machiry, A.
"Finding 709 Defects in 258 Projects: An Experience Report on Applying
CodeQL to Open-Source Embedded Software (Experience Paper)."
*Proc. ACM on Software Engineering* 2(ISSTA):1077--1100, 2025.

| DOI: https://doi.org/10.1145/3728923
| Preprint (2023, as "An Empirical Study on the Use of Static Analysis Tools
  in Open Source Embedded Software"): https://machiry.github.io/files/emsast.pdf

How embedded open-source projects use static analysis; developers cite
perceived ineffectiveness and false positives as reasons for limited
adoption.

----

**[NCC-Group]** Boone, J.
"Best Practices for the use of Static Code Analysis within a Real-World
Secure Development Lifecycle." NCC Group, 2015.

| PDF: https://www.nccgroup.com/media/vegkqamt/_ncc-group-best-practices-for-static-code-aanalysis.pdf

Industry guidance on deploying static analysis effectively, managing
FP rates, and integrating into development workflows.

False Positive Rate Benchmarks
------------------------------

**[CASTLE2025]** Dubniczky, R. A., Horvát, K. Z., Bisztray, T., Ferrag,
M. A., Cordeiro, L. C., and Tihanyi, N.
"CASTLE: Benchmarking Dataset for Static Code Analyzers and LLMs towards CWE
Detection." *TASE 2025*, LNCS, pp. 253--272.

| DOI: https://doi.org/10.1007/978-3-031-98208-8_15
| arXiv: https://arxiv.org/abs/2503.09433

A hand-crafted micro-benchmark for static analyzers and LLMs; its scoring
considers true and false positives and vulnerability severity.

----

**[Christakis2016]** Christakis, M. and Bird, C.
"What Developers Want and Need from Program Analysis: An Empirical Study."
*Proc. 31st IEEE/ACM International Conference on Automated Software
Engineering (ASE 2016)*, pp. 332--343.

| DOI: https://doi.org/10.1145/2970276.2970347

A survey of Microsoft developers. 90% of respondents accept a
false-positive rate of up to 5%, 47% accept up to 15%, and only 24% accept
20%; from this the authors recommend that program-analysis designers aim for
a false-positive rate no higher than 15--20%.

Industry FP Rate Context
~~~~~~~~~~~~~~~~~~~~~~~~~

- **At most 15--20% FP rate**: the target [Christakis2016] recommends to
  analysis designers, drawn from its survey. It is not a rate most
  respondents accepted: only 24% accepted 20%, and 47% accepted 15%.
- **5% FP rate**: a vendor's stated target for its own analyzer, not an
  independent measurement (DeepSource,
  https://deepsource.com/blog/how-deepsource-ensures-less-false-positives).

Standards & Specifications
--------------------------

**[CERT-C]** Software Engineering Institute.
"SEI CERT C Coding Standard."

| https://cmu-sei.github.io/secure-coding-standards/sei-cert-c-coding-standard

|rules_total| rules across 17 categories. The rule set implemented by aurora-lint.

----

**[SARIF-2.1]** OASIS.
"Static Analysis Results Interchange Format (SARIF) Version 2.1.0."

| https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

The output format used by aurora-lint for CI/CD integration.
