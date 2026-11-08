# Source version and reproducibility changes

- Backend, verifier, engine, inference adapter and fixed runner are unchanged from the executed app source. This source version has not been deployed.
- The judge UI makes its policy-enforcement sentence conditional so a negative imported result does not claim a mitigation block.
- The frontend lock is the exact successful resolved Linux build lock. Direct requirements are unchanged; optional dependency records are corrected.
- The public exporter imports the scanner from the standalone package_source module rather than the earlier packaging module. Its evidence validation logic is unchanged.
- The Caddy template explicitly disables automatic HTTPS and uses HTTP. It preserves the exact public GET allowlist and private-route denial. These are source templates, not changes to the running demo.
- scripts/controlled_model.py adapts the recorded two-request model control. The prompt, note, payloads, response requirements, gate, stage verification and exact replay are retained. Private host/image/path bindings are replaced by fresh local image-bound configuration. Durable file/config helpers are self-contained. This version is not byte-identical to the hosted runner and has only mock/offline validation in this source release.
- Documentation describes public setup, evidence provenance, current HTTP behavior and security limits. Environment examples contain empty secret fields. The operator health-check file is named check_operator.py.
- Only sanitized recorded snapshots are distributed. Run state, private audits, raw provider responses, account data and rendered media are excluded. The offline replay is separately and explicitly labeled simulation.
- Project source is MIT licensed; dependencies retain their licenses.
