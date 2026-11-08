# Source validation

Reference local platform: macOS arm64, Python 3.12.15, Node 22.23.3, npm 11.6.2.

| Check | Result |
| --- | --- |
| Offline Python suite | 89 passed, 7 real Docker cases deselected, 1 upstream Starlette/AnyIO deprecation warning |
| Controlled-model tests | Synthetic MockTransport/executor cases, including process concurrency/crash, request-budget mutations, wrong model/finish/schema, cleanup and persistence failures |
| Clean frontend install | npm ci --offline --ignore-scripts --no-audit --no-fund passed using an existing local package cache |
| TypeScript / Vite build | Passed |
| Production-bundle browser regression | Isolated sandboxed Chrome; synthetic localhost API fixtures; positive and negative copy, experiment selection, missing/stale states and recovery passed |
| Extracted source tests | 89 passed, 7 deselected, 1 upstream warning |
| Extracted frontend | Clean cached npm ci, typecheck and build passed |
| Source archive rebuild | Byte-exact deterministic gzip/tar rebuild from extracted sources |
| Release checks | Explicit allowlist, regular files, path/symlink rejection, credential-pattern scan and documentation privacy review |

Tests block actual network connects and Docker subprocesses. Provider results in tests are synthetic. No provider request, actual Docker execution or host operation is part of these source checks. Heuristic scanning cannot prove the absence of all secrets or vulnerabilities; the explicit source set and exact manifest remain reviewable.

This source version and sanitized controlled-model CLI have not been executed on Linux or against a real provider/worker. Linux worker, provider, Caddy/systemd installation and live-host browser acceptance for this source version are unrun. Recorded hosted results and the prior successful Linux lockfile build are separate historical evidence, not tests of this adaptation. The judge text-only negative-result change passed local production-bundle browser regression in addition to TypeScript/build validation.

The recorded public snapshots keep their original timestamps. Their generated_at values were not refreshed for this release. The original executed source and this reproducibility-oriented source version are distinguished in RELEASE_NOTES.md.

The local browser regression used the exact compiled candidate JavaScript and CSS with intercepted localhost responses. A positive policy finding and a synthetic no-attack result were test inputs only. The negative result displayed that no mitigation block was demonstrated and omitted the positive policy-enforcement claim. Switching between model/protected-write records, missing snapshot, stale-but-readable snapshot and recovery states passed. No external or unexpected request and no page error occurred. Provider/Docker execution and workspace-token controls remained absent. Three private QA screenshots were visually reviewed for readability; they are not execution evidence and are not included in the source release. No signed-in browser state, live host or external service was accessed.
