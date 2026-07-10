# Releasing the npm packages

The repository publishes two packages. Release them in this order so the SDK can resolve its workspace dependency to a version that already exists on npm:

1. `smart-account-kit-bindings`
2. `smart-account-kit`

For the current Protocol 27 release, the checked-in target versions are `smart-account-kit-bindings@0.2.0` and `smart-account-kit@0.3.0`. At release preparation on 2026-07-09, the versions published on npm were `0.1.2` and `0.2.10`, respectively; the preflight commands below are the source of truth when you publish.

## Prerequisites

- Node.js 22 or newer
- pnpm 10 or newer
- Stellar CLI 27 or newer when regenerating bindings
- npm publish access to both packages
- A clean tracked Git worktree; both release scripts stop if tracked changes are present

Authenticate and confirm the current registry state:

```bash
npm login
npm whoami
npm view smart-account-kit-bindings version
npm view smart-account-kit version
```

## Regenerate bindings from the optimized contract

Regenerate whenever the smart-account contract interface changes. From the `smart-account-kit` repository, with `stellar-contracts` checked out as a sibling directory:

```bash
CONTRACTS=../stellar-contracts

(
  cd "$CONTRACTS"
  stellar contract build \
    --locked \
    --optimize=true \
    --package multisig-account-example
)

ACCOUNT_WASM="$CONTRACTS/target/wasm32v1-none/release/multisig_account_example.wasm" \
BINDINGS_VERSION=0.2.0 \
pnpm build:bindings
```

Stellar CLI 27 writes the optimized output to the standard `.wasm` path shown above; the build summary confirms the optimized and original sizes.

Review and commit regenerated sources before publishing. The generation script preserves the requested binding version and installs the repository's maintained package README after the Stellar CLI generator runs.

## Validate

```bash
pnpm install --frozen-lockfile
pnpm test --run
pnpm build
pnpm --filter smart-account-kit-demo build
pnpm --filter indexer-demo build
git diff --check
git status --short
```

Commit any intended changes before continuing. Uncommitted tracked changes cause the release scripts to exit.

## Authenticated dry run

The dry-run mode verifies npm authentication, reads the live registry versions, and shows the intended publish versions. It does not build or upload a package.

```bash
pnpm release:bindings --version 0.2.0 --dry-run
pnpm release --version 0.3.0 --bindings-version 0.2.0 --dry-run
```

Do not insert an extra `--` after the pnpm script name; pnpm forwards it to these shell scripts as an argument.

## Publish and verify

```bash
pnpm release:bindings --version 0.2.0
npm view smart-account-kit-bindings@0.2.0 version

pnpm release --version 0.3.0 --bindings-version 0.2.0
npm view smart-account-kit@0.3.0 version
npm view smart-account-kit@0.3.0 dependencies
```

If npm requires a one-time password, append `--otp <fresh-code>` to each `pnpm release...` command. Use a fresh code for the second publish if the first one expires.

The scripts intentionally use exact versions here. A second attempt after a successful publish will fail because npm package versions are immutable; check `npm view` before retrying.
