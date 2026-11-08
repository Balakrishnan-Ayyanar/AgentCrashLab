# Reproduction and validation scope

Python 3.12 with the runtime pins and pytest 8.3.5, Node 22.23.3 / npm 11.6.2 are the local reference tooling. The recorded deployed Linux build used existing Node 24.19 and the successful resolved lock. This release candidate uses that lock byte-for-byte. No actual Docker or paid provider call is part of the documented offline test command.

## Dependency-lock correction

The sealed original lock SHA256 was 87e57ca46dbfa707881f2a0055c22d4df86a42cf041e436a5025eb0822c31ca6. Linux npm ci rejected missing/inconsistent optional WASM dependency records. The successful build-copy lock SHA256 is 43b2c1b68ec7af315592ce10bc0e5f32c7fe60f575cac15da5bbad8a0fe2fe03. This candidate includes that exact non-secret lockfile. The original executed release remains distinct from this candidate.

Root direct dependencies are unchanged. The top-level @emnapi/wasi-threads changes 1.2.2 to 1.2.3. Nested @emnapi/core 1.11.1, @emnapi/runtime 1.11.1 and @emnapi/wasi-threads 1.2.2 records are added under @rolldown/binding-wasm32-wasi. Resolved URLs/integrity values follow those package versions. No dependency is silently upgraded by the candidate build: use npm ci, not npm install. A clean package cache may require official registry downloads; these are not model/provider calls. Locally available package cache may be used with --offline; record failure honestly if an entry is unavailable.

## Offline tests

Run the README's pytest command with seven real Docker tests excluded. Provider cases use MockTransport and synthetic credentials. Judge tests reconstruct synthetic private-shaped records only under pytest temporary paths; they never load private deployment evidence. Fixture replay is deterministic simulation. The two checked-in snapshots are allowlisted recorded data, not newly generated observations. Preserve their timestamps.

`SOURCE_MANIFEST.json` records SHA256 for every explicit source path except itself. `RELEASE_ALLOWLIST.json` controls packaging. `scripts.package_source` rejects symlinks, path traversal, unexpected archive members, unsafe types and size/pattern failures; output is deterministic gzip/tar with normalized metadata. The manifest is included in the archive without attempting to hash itself. Verify an extracted archive by running the same offline tests/build and packaging it to a new output path; compare archive hashes/bytes.

The live hosted evidence predates this candidate's lockfile/import/template/documentation changes. Past Linux checks are not a claim that the candidate was executed on Linux. The accompanying public release validation document reports only actually completed local checks. The opt-in controlled model runner is excluded from automatic tests and startup. No CI workflow or automatic paid execution is enabled.
