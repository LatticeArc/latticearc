# OSS-Fuzz integration scaffold

This directory vendors the three files google/oss-fuzz needs to run
continuous fuzzing against `latticearc`. Nothing here runs in our own
CI — the files live here so we can keep them under version control
alongside the fuzz targets themselves; the actual fuzz scheduling
lives in google/oss-fuzz.

## Contents

| File           | Purpose                                                |
| -------------- | ------------------------------------------------------ |
| `project.yaml` | Project metadata + enabled sanitizers                  |
| `Dockerfile`   | Build image: base-builder-rust + aws-lc-rs deps        |
| `build.sh`     | Entrypoint: builds every `[[bin]]` from `fuzz/Cargo.toml` |

## Integration

To onboard onto OSS-Fuzz, file a PR against
`https://github.com/google/oss-fuzz` adding
`projects/latticearc/{project.yaml,Dockerfile,build.sh}` as exact
copies of the files in this directory. See the OSS-Fuzz new-project
guide: https://google.github.io/oss-fuzz/getting-started/new-project-guide/rust-lang/

Once accepted, google/oss-fuzz infrastructure:

- Clones `github.com/LatticeArc/latticearc` periodically
- Builds every fuzz target under the sanitizers declared in `project.yaml`
  (`address`, `undefined` today)
- Runs each target continuously with findings reported to the
  `primary_contact` / `auto_ccs` addresses

## Verifying locally

Upstream OSS-Fuzz ships a `helper.py` that exercises these three files
against the same base image they use in production. To dry-run before
filing the PR:

```bash
git clone https://github.com/google/oss-fuzz /tmp/oss-fuzz
mkdir -p /tmp/oss-fuzz/projects/latticearc
cp fuzz/oss-fuzz/{project.yaml,Dockerfile,build.sh} \
   /tmp/oss-fuzz/projects/latticearc/
cd /tmp/oss-fuzz
python3 infra/helper.py build_image latticearc
python3 infra/helper.py build_fuzzers latticearc
python3 infra/helper.py check_build latticearc
```

Each step should complete cleanly before filing the upstream PR.

## Open items

- **Memory sanitizer** intentionally omitted from `project.yaml`. aws-lc-rs
  does not yet expose an MSan-safe feature flag (tracked upstream as
  `aws/aws-lc-rs#1077`). Add `- memory` to the `sanitizers:` list
  when that PR ships, and flip `.github/workflows/sanitizers.yml`
  from `continue-on-error: true` to `false` at the same time.
- **Seed corpora**: `build.sh` does not currently zip and install
  `<target>_seed_corpus.zip`. Targets that could benefit (e.g.,
  JSON deserialization, signature parsing) should accumulate corpora
  under `fuzz/corpus/<target>/` and be added to the seed-install loop.
