//! Generated protobuf types for the TinyWeb schemas.
//!
//! The types are generated at build time by `build.rs` (prost-build)
//! from the schemas in `../../proto` (`envelope.proto`,
//! `content.proto`, `api.proto`, `message.proto`,
//! `client_request.proto`, package `tinyweb`). They provide the
//! protocol types (e.g. `Envelope`, `Message`, `ClientRequest`,
//! and the content message types).

include!(concat!(env!("OUT_DIR"), "/tinyweb.rs"));
