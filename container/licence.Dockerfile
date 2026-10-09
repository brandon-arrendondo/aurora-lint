# The Win32 corpus's dependency set, added on THIS machine to the shared
# benchmark image (container/benchmark.Dockerfile, which is built without
# it). The set is the Windows SDK and MSVC CRT headers, which xwin downloads
# from Microsoft's servers under Microsoft's licence terms: building this
# file with --build-arg ACCEPT_MICROSOFT_LICENSE=true accepts them for the
# machine that builds it. Never push the result to a registry or copy it to
# another machine; each machine builds its own.
#
#   podman build --platform linux/amd64 -f container/licence.Dockerfile \
#     --build-arg BENCH_IMAGE=<registry>/aurora-bench@sha256:<digest> \
#     --build-arg ACCEPT_MICROSOFT_LICENSE=true -t aurora-bench:dev .
#
# The result carries the full environment manifest: the same pin as the
# benchmark environment this commit declares (data/benchmark_environment.json).

ARG BENCH_IMAGE
FROM ${BENCH_IMAGE}
ARG ACCEPT_MICROSOFT_LICENSE=false
RUN [ "$ACCEPT_MICROSOFT_LICENSE" = true ] || { \
      echo "Building this image accepts Microsoft's licence terms for the Windows SDK and MSVC CRT:" >&2; \
      echo "pass --build-arg ACCEPT_MICROSOFT_LICENSE=true to accept them for this machine." >&2; \
      exit 1; }
RUN cd /opt/aurora-bench \
 && export AURORA_ACCEPT_MICROSOFT_LICENSE=1 \
 && for f in data/benchmark_deps/*.json; do \
      python3 -m bench.deps fetch "$(basename "$f" .json)" || exit 1; \
    done \
 && rm -rf /bench/deps/.cache \
 && python3 -m bench.environment write /etc/aurora-bench/environment.json
