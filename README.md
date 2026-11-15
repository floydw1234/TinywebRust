# TinywebRust

The native Rust build of **tinywebStack** — a private family stack (chat,
location, events, files/photos, dashboard) that runs on hardware you own, as
one cohesive system: a gossip protocol (UDP) plus an HTTP API, with content
carried as protobuf envelopes and stored in SQLite.

This repo stands alone. The earlier C prototype (NPressInc/TinyWebC) is
history — it proved the full-stack native approach; this is the build that
carries it forward.

## Layout

- `rust/` — the node: gossip transport, HTTP API, store, validation,
  discovery, encryption, keystore. One binary.
- `proto/` — the wire definitions (protobuf schemas) the node is built from.
- `webui/` — the React test page: a dashboard + app mirror of the node API,
  used to test the full experience end to end as features land.
- `DESIGN.md` — the integrated design: identity/enrollment, the envelope
  content model, the store schema, and the API surface for the full family
  feature set.

## Build the node

```sh
cd rust
cargo build
cargo test
```

Run it:

```sh
./target/debug/tinyweb --id 1 --gossip-port 9000 --api-port 8000
```

## Run the test page

```sh
cd webui
npm install
npm run dev
```

The dev server proxies `/api` to a node on `localhost:8000`. It can be
locked with a private API key configured in `webui/.env.local` — that file
is gitignored and must never be committed.
