# @abitious/cli

Ship Node.js native addons (`.node`) as **compressed, self-loading hybrid files**.

This is the main package: it installs the `abi` build CLI and a platform loader that
resolves the prebuilt **stub** and **host producer** for your platform from the
matching optional dependency (`@abitious/<triple>`).

## Install

```sh
npm install -D @abitious/cli
```

The correct platform package (`@abitious/darwin-arm64`, `@abitious/linux-x64-gnu`, …)
is installed automatically as an optional dependency for your OS / CPU / libc.

## Use

```sh
abi build --compress          # build the host cdylib and wrap it into a hybrid .node
```

With `@abitious/cli` installed, `abi build --compress` auto-resolves the stub from the
installed platform package — no `--stub` needed (pass `--stub <path>` to override).

## Programmatic

```js
const { stub, bin, triple } = require('@abitious/cli')
// stub → the prebuilt generic stub .node for this host
// bin  → the native `abi` producer binary
```

## License

MIT.
