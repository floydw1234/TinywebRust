//! Peer discovery.
//!
//! Rust counterpart of the C discovery package
//! `src/packages/discovery/` (`discovery.c` plus the
//! `tailscale_discovery.c`, `dns_pattern_discovery.c`, and
//! `static_discovery.c` backends): finding gossip peers via
//! Tailscale, DNS hostname patterns, or a static configured peer
//! list, and registering them with the gossip service/store.
//!
//! The public surface mirrors `discovery.h`: [`discover_peers`]
//! routes on `config.discovery_mode` to one of
//! [`discover_tailscale_peers`], [`discover_dns_pattern_peers`], or
//! [`discover_static_peers`], and [`discovery_mode_from_string`]
//! converts the configured mode string. Where C returns
//! `0`/`-1`, these return `Ok(peers)`/`Err(..)`; the peer list
//! holds exactly the peers the C code would have counted in
//! `peers_found` (registered with both the gossip service and the
//! peer store).
//!
//! Registration is abstracted by [`PeerSink`]: C calls
//! `gossip_service_add_peer` plus `gossip_peers_add_or_update`, and
//! counts a peer only when both succeed, so a sink models the two
//! as one fallible operation. A failed registration is logged by C
//! and skipped, never fatal; backends mirror that by omitting the
//! peer from the result instead of propagating the sink's error.
//! [`InMemoryPeerSink`] reproduces `gossip_service_add_peer`'s
//! in-memory semantics (dedupe by address+port, 32-peer cap).
//!
//! Graceful-fallback cases in C (return `0` with no peers) stay
//! graceful here: Tailscale unavailable after retries, unparseable
//! Tailscale output, `none`/unknown mode, and an empty static list
//! all yield `Ok(vec![])`. Only the cases C reports as `-1`
//! (missing `hostname_prefix`/`dns_domain`) become `Err`.

use std::fmt;
use std::net::ToSocketAddrs;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::Value;

/// Gossip port used when a discovery mechanism does not carry one
/// (`GOSSIP_PORT` in the C backends).
pub const GOSSIP_PORT: u16 = 9000;

/// Highest node index probed by DNS-pattern discovery
/// (`MAX_NODE_INDEX` in `dns_pattern_discovery.c`).
pub const MAX_NODE_INDEX: u32 = 99;

/// Capacity of the gossip service peer table (`GOSSIP_MAX_PEERS`).
pub const GOSSIP_MAX_PEERS: usize = 32;

/// How many times Tailscale discovery retries
/// `tailscale status --json` (`TAILSCALE_RETRY_COUNT`).
pub const TAILSCALE_RETRY_COUNT: u32 = 30;

/// Delay between Tailscale status attempts
/// (`TAILSCALE_RETRY_DELAY_SECONDS`).
pub const TAILSCALE_RETRY_DELAY: Duration = Duration::from_secs(2);

/// Discovery mechanism, counterpart of C `DiscoveryMode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryMode {
    /// `DISCOVERY_TAILSCALE`
    Tailscale,
    /// `DISCOVERY_DNS_PATTERN`
    DnsPattern,
    /// `DISCOVERY_STATIC`
    Static,
    /// `DISCOVERY_NONE`
    None,
}

/// Counterpart of C `discovery_mode_from_string`: case-insensitive,
/// empty or unknown strings yield [`DiscoveryMode::None`].
pub fn discovery_mode_from_string(mode_str: &str) -> DiscoveryMode {
    if mode_str.eq_ignore_ascii_case("tailscale") {
        DiscoveryMode::Tailscale
    } else if mode_str.eq_ignore_ascii_case("dns_pattern") {
        DiscoveryMode::DnsPattern
    } else if mode_str.eq_ignore_ascii_case("static") {
        DiscoveryMode::Static
    } else {
        // "none" and every unknown mode both map to None, as in C.
        DiscoveryMode::None
    }
}

/// Errors reported by discovery, for the cases where C returns
/// `-1` (plus sink/parse failures that callers may inspect).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryError {
    /// Missing/invalid configuration (C: backend argument checks).
    InvalidArgument(String),
    /// Unparseable JSON (Tailscale status or network config).
    InvalidJson(String),
    /// Unparseable `hostname[:port]` peer string.
    InvalidPeer(String),
    /// Peer registration failed (gossip service / peer store).
    Sink(String),
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DiscoveryError::InvalidArgument(msg) => {
                write!(f, "invalid discovery argument: {msg}")
            }
            DiscoveryError::InvalidJson(msg) => {
                write!(f, "invalid JSON: {msg}")
            }
            DiscoveryError::InvalidPeer(msg) => {
                write!(f, "invalid peer: {msg}")
            }
            DiscoveryError::Sink(msg) => {
                write!(f, "peer registration failed: {msg}")
            }
        }
    }
}

impl std::error::Error for DiscoveryError {}

/// A discovered gossip peer: the C code passes exactly this pair
/// to `gossip_service_add_peer` and `gossip_peers_add_or_update`
/// (with `api_port` 0 and no pubkey/tags), matching `GossipPeer`'s
/// `address`/`port` fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Peer {
    /// Hostname (FQDN when the source provides one) or address.
    pub hostname: String,
    /// Gossip port.
    pub port: u16,
}

impl Peer {
    /// Create a peer from a hostname and gossip port.
    pub fn new(hostname: impl Into<String>, port: u16) -> Self {
        Peer {
            hostname: hostname.into(),
            port,
        }
    }
}

/// The discovery-relevant subset of C `NodeConfig` (see
/// `src/packages/utils/config.h`): the inputs the backends read.
/// In C these come from `network_config.json`
/// (`docker.discovery.*`, the node's `hostname`/`peers`) with
/// `TINYWEB_*` environment variables merged over them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    /// Mode string as configured; converted by
    /// [`discovery_mode_from_string`] on each run, as in C.
    pub discovery_mode: String,
    /// Own hostname, used for self-skipping (may be empty).
    pub hostname: String,
    /// Hostname prefix for Tailscale/DNS-pattern matching.
    pub hostname_prefix: String,
    /// DNS domain for DNS-pattern discovery.
    pub dns_domain: String,
    /// Static peers, each `hostname[:port]` (C `config->peers`).
    pub peers: Vec<String>,
}

impl Default for DiscoveryConfig {
    /// Matches `config_set_defaults`: mode `static`, the rest
    /// empty.
    fn default() -> Self {
        DiscoveryConfig {
            discovery_mode: "static".to_string(),
            hostname: String::new(),
            hostname_prefix: String::new(),
            dns_domain: String::new(),
            peers: Vec::new(),
        }
    }
}

impl DiscoveryConfig {
    /// The configured mode as a [`DiscoveryMode`].
    pub fn mode(&self) -> DiscoveryMode {
        discovery_mode_from_string(&self.discovery_mode)
    }

    /// Defaults with the `TINYWEB_DISCOVERY_MODE`,
    /// `TINYWEB_HOSTNAME_PREFIX`, and `TINYWEB_DNS_DOMAIN`
    /// environment overrides applied, mirroring
    /// `config_load_from_env` merged by `config_merge` (an empty
    /// variable does not override).
    pub fn from_env() -> Self {
        let mut config = DiscoveryConfig::default();
        if let Ok(mode) = std::env::var("TINYWEB_DISCOVERY_MODE") {
            if !mode.is_empty() {
                config.discovery_mode = mode;
            }
        }
        if let Ok(prefix) = std::env::var("TINYWEB_HOSTNAME_PREFIX") {
            if !prefix.is_empty() {
                config.hostname_prefix = prefix;
            }
        }
        if let Ok(domain) = std::env::var("TINYWEB_DNS_DOMAIN") {
            if !domain.is_empty() {
                config.dns_domain = domain;
            }
        }
        config
    }

    /// Extract the discovery inputs for `node_id` from the text of
    /// a `network_config.json`, mirroring the discovery-relevant
    /// parts of `config_load_node_from_network_config`: the node is
    /// found in the top-level `nodes` array when present, otherwise
    /// the root itself must carry a matching `id`; `hostname` and
    /// `peers` come from the node object, and
    /// `docker.discovery.mode` / `.hostname_prefix` /
    /// `.dns_pattern.domain` from the root.
    pub fn from_network_config_json(
        json: &str,
        node_id: &str,
    ) -> Result<Self, DiscoveryError> {
        let root: Value = serde_json::from_str(json)
            .map_err(|e| DiscoveryError::InvalidJson(e.to_string()))?;
        let mut config = DiscoveryConfig::default();

        let node: &Value = match root.get("nodes").and_then(Value::as_array) {
            Some(nodes) => nodes
                .iter()
                .find(|n| n.get("id").and_then(Value::as_str) == Some(node_id))
                .ok_or_else(|| {
                    DiscoveryError::InvalidArgument(format!(
                        "node {node_id} not found in config"
                    ))
                })?,
            None => {
                if root.get("id").and_then(Value::as_str) != Some(node_id) {
                    return Err(DiscoveryError::InvalidArgument(format!(
                        "node {node_id} not found in config"
                    )));
                }
                &root
            }
        };

        if let Some(hostname) = node.get("hostname").and_then(Value::as_str) {
            config.hostname = hostname.to_string();
        }
        if let Some(peers) = node.get("peers").and_then(Value::as_array) {
            // C leaves non-string entries NULL and the static
            // backend skips them; dropping them here is equivalent.
            config.peers = peers
                .iter()
                .filter_map(|p| p.as_str().map(str::to_string))
                .collect();
        }

        if let Some(discovery) = root.get("docker").and_then(|d| d.get("discovery")) {
            if let Some(mode) = discovery.get("mode").and_then(Value::as_str) {
                config.discovery_mode = mode.to_string();
            }
            if let Some(prefix) =
                discovery.get("hostname_prefix").and_then(Value::as_str)
            {
                config.hostname_prefix = prefix.to_string();
            }
            if let Some(domain) = discovery
                .get("dns_pattern")
                .and_then(|d| d.get("domain"))
                .and_then(Value::as_str)
            {
                config.dns_domain = domain.to_string();
            }
        }

        Ok(config)
    }
}

/// Destination for discovered peers: models C's pair of
/// `gossip_service_add_peer` (gossip service) and
/// `gossip_peers_add_or_update(hostname, port, 0, NULL)`
/// (peer store) calls. The store write is address-only:
/// discovery never grants trust (DESIGN.md §10). Returning
/// `Err` means the peer was not registered; backends then
/// skip it without failing, as C does.
pub trait PeerSink {
    /// Register one peer with the gossip service and peer store.
    fn add_peer(&mut self, peer: &Peer) -> Result<(), DiscoveryError>;
}

/// In-memory [`PeerSink`] with `gossip_service_add_peer`'s
/// semantics: adding an already-known address+port succeeds
/// without duplicating it, and the table holds at most
/// [`GOSSIP_MAX_PEERS`] peers. The capacity check runs before the
/// duplicate check, as in C, so even a duplicate is rejected once
/// the table is full.
#[derive(Debug, Default)]
pub struct InMemoryPeerSink {
    peers: Vec<Peer>,
}

impl InMemoryPeerSink {
    /// Create an empty sink.
    pub fn new() -> Self {
        InMemoryPeerSink { peers: Vec::new() }
    }

    /// The registered peers, deduplicated by address+port.
    pub fn peers(&self) -> &[Peer] {
        &self.peers
    }
}

impl PeerSink for InMemoryPeerSink {
    fn add_peer(&mut self, peer: &Peer) -> Result<(), DiscoveryError> {
        if self.peers.len() >= GOSSIP_MAX_PEERS {
            return Err(DiscoveryError::Sink(format!(
                "peer table full ({GOSSIP_MAX_PEERS} peers)"
            )));
        }
        if !self.peers.contains(peer) {
            self.peers.push(peer.clone());
        }
        Ok(())
    }
}

/// Add `peer` to `sink`, recording it in `registered` on success.
/// Registration failure is not fatal in C (it only keeps the peer
/// out of `peers_found`), so the error is dropped here.
fn register_peer<S: PeerSink + ?Sized>(
    sink: &mut S,
    peer: &Peer,
    registered: &mut Vec<Peer>,
) {
    if sink.add_peer(peer).is_ok() {
        registered.push(peer.clone());
    }
}

/// Hostname up to the first `.` (the whole string when it has
/// none), as the C Tailscale backend extracts for prefix matching
/// and self-comparison. C copies into a 256-byte buffer; the
/// truncation is not reproduced.
fn short_hostname(hostname: &str) -> &str {
    match hostname.find('.') {
        Some(idx) => &hostname[..idx],
        None => hostname,
    }
}

/// C `matches_hostname_prefix`: false for an empty prefix,
/// otherwise a case-sensitive prefix test.
fn matches_hostname_prefix(hostname: &str, prefix: &str) -> bool {
    !prefix.is_empty() && hostname.starts_with(prefix)
}

/// C `extract_node_index`: the two-digit numeric suffix after
/// `prefix` (e.g. `tw_node01` with prefix `tw_node` yields 1), or
/// `None` when the hostname is not exactly prefix plus two digits.
/// Ported for parity; the C helper is likewise unused by its
/// backend's peer loop.
#[allow(dead_code)]
fn extract_node_index(hostname: &str, prefix: &str) -> Option<u32> {
    let (hostname, prefix) = (hostname.as_bytes(), prefix.as_bytes());
    if hostname.len() < prefix.len() + 2 {
        return None;
    }
    if &hostname[..prefix.len()] != prefix {
        return None;
    }
    let suffix = &hostname[prefix.len()..];
    if suffix.len() != 2 {
        return None;
    }
    if !suffix[0].is_ascii_digit() || !suffix[1].is_ascii_digit() {
        return None;
    }
    Some(u32::from(suffix[0] - b'0') * 10 + u32::from(suffix[1] - b'0'))
}

/// C `atoi`: skips leading whitespace, accepts an optional sign,
/// then reads digits up to the first non-digit; no digits yields
/// 0 (so trailing junk after the digits is ignored).
fn c_atoi(s: &str) -> i32 {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r') {
        i += 1;
    }
    let mut sign: i64 = 1;
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        if bytes[i] == b'-' {
            sign = -1;
        }
        i += 1;
    }
    let mut value: i64 = 0;
    let mut any_digits = false;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        any_digits = true;
        value = value
            .saturating_mul(10)
            .saturating_add(i64::from(bytes[i] - b'0'));
        i += 1;
    }
    if !any_digits {
        return 0;
    }
    (sign * value).clamp(i64::from(i32::MIN), i64::from(i32::MAX)) as i32
}

/// Parse one static peer string, C `parse_peer_string`:
/// `hostname:port` splits at the first `:` and parses the rest
/// with `atoi` semantics; without a colon the port defaults to
/// [`GOSSIP_PORT`]. Hostnames of 256 bytes or more (the C buffer
/// size, port part excluded) and ports outside 1..=65535 fail.
/// Like C, an empty hostname is not rejected.
pub fn parse_peer_string(peer_str: &str) -> Result<Peer, DiscoveryError> {
    match peer_str.find(':') {
        Some(colon) => {
            let hostname = &peer_str[..colon];
            if hostname.len() >= 256 {
                return Err(DiscoveryError::InvalidPeer(format!(
                    "hostname too long in peer string: {peer_str}"
                )));
            }
            let port_num = c_atoi(&peer_str[colon + 1..]);
            if !(1..=65535).contains(&port_num) {
                return Err(DiscoveryError::InvalidPeer(format!(
                    "invalid port in peer string: {peer_str}"
                )));
            }
            Ok(Peer::new(hostname, port_num as u16))
        }
        None => {
            if peer_str.len() >= 256 {
                return Err(DiscoveryError::InvalidPeer(format!(
                    "hostname too long in peer string: {peer_str}"
                )));
            }
            Ok(Peer::new(peer_str, GOSSIP_PORT))
        }
    }
}

/// The peers a static run would register, before the sink is
/// involved: each configured string parsed in order, unparseable
/// ones skipped, and self (parsed hostname equal to
/// `config.hostname`, whatever the port) skipped, exactly as
/// `discover_static_peers` filters before calling
/// `gossip_service_add_peer`. Duplicates are kept; the gossip
/// service deduplicates them when they are registered.
pub fn parse_static_peers(config: &DiscoveryConfig) -> Vec<Peer> {
    config
        .peers
        .iter()
        .filter_map(|peer_str| parse_peer_string(peer_str).ok())
        .filter(|peer| {
            config.hostname.is_empty() || peer.hostname != config.hostname
        })
        .collect()
}

/// Static discovery, C `discover_static_peers`: registers every
/// peer from `config.peers`. An empty list is not an error.
pub fn discover_static_peers<S: PeerSink + ?Sized>(
    sink: &mut S,
    config: &DiscoveryConfig,
) -> Result<Vec<Peer>, DiscoveryError> {
    let mut registered = Vec::new();
    for peer in parse_static_peers(config) {
        register_peer(sink, &peer, &mut registered);
    }
    Ok(registered)
}

/// Whether `hostname` resolves, C `hostname_resolves`
/// (`getaddrinfo` with `AF_UNSPEC`/`SOCK_STREAM`).
fn hostname_resolves(hostname: &str) -> bool {
    match (hostname, 0u16).to_socket_addrs() {
        Ok(mut addrs) => addrs.next().is_some(),
        Err(_) => false,
    }
}

/// The hostnames DNS-pattern discovery probes:
/// `{hostname_prefix}{01..=99}.{dns_domain}` with zero-padded
/// indices, excluding self (an exact match with
/// `config.hostname` is skipped before resolution, as in C).
pub fn dns_pattern_candidates(config: &DiscoveryConfig) -> Vec<String> {
    (1..=MAX_NODE_INDEX)
        .map(|i| format!("{}{:02}.{}", config.hostname_prefix, i, config.dns_domain))
        .filter(|hostname| {
            config.hostname.is_empty() || hostname.as_str() != config.hostname
        })
        .collect()
}

/// DNS-pattern discovery with an injectable resolver, C
/// `discover_dns_pattern_peers`: every candidate that resolves
/// is registered on [`GOSSIP_PORT`].
pub fn discover_dns_pattern_peers_with<S: PeerSink + ?Sized, R: Fn(&str) -> bool>(
    sink: &mut S,
    config: &DiscoveryConfig,
    resolver: R,
) -> Result<Vec<Peer>, DiscoveryError> {
    if config.hostname_prefix.is_empty() {
        return Err(DiscoveryError::InvalidArgument(
            "hostname_prefix not configured".to_string(),
        ));
    }
    if config.dns_domain.is_empty() {
        return Err(DiscoveryError::InvalidArgument(
            "dns_domain not configured".to_string(),
        ));
    }
    let mut registered = Vec::new();
    for hostname in dns_pattern_candidates(config) {
        if !resolver(&hostname) {
            continue;
        }
        register_peer(sink, &Peer::new(hostname, GOSSIP_PORT), &mut registered);
    }
    Ok(registered)
}

/// DNS-pattern discovery using live DNS resolution; see
/// [`discover_dns_pattern_peers_with`].
pub fn discover_dns_pattern_peers<S: PeerSink + ?Sized>(
    sink: &mut S,
    config: &DiscoveryConfig,
) -> Result<Vec<Peer>, DiscoveryError> {
    discover_dns_pattern_peers_with(sink, config, hostname_resolves)
}

/// Run `tailscale status --json` (stderr discarded, as C's
/// `2>/dev/null`), returning its stdout on success. C reads into
/// a fixed 8192-byte buffer and truncates longer output; that
/// truncation is deliberately not reproduced — the full output
/// is parsed instead.
fn execute_tailscale_status() -> Option<String> {
    let output = Command::new("tailscale")
        .args(["status", "--json"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout).ok()
}

/// Extract the peers from `tailscale status --json` output, the
/// filtering core of C `discover_tailscale_peers`: for each entry
/// of the top-level `Peer` object, keep it when its `DNSName`'s
/// short hostname (up to the first `.`) starts with
/// `config.hostname_prefix`, it is not self (short hostnames
/// compared, when `config.hostname` is set), and `Online` is
/// `true`. The peer keeps the full `DNSName` and gets
/// [`GOSSIP_PORT`]. A missing/non-object `Peer` yields no peers;
/// only unparseable JSON is an error. Peers follow serde_json's
/// map order (keys sorted), where C used document order; the
/// resulting set is the same.
pub fn parse_tailscale_status(
    json: &str,
    config: &DiscoveryConfig,
) -> Result<Vec<Peer>, DiscoveryError> {
    let root: Value = serde_json::from_str(json)
        .map_err(|e| DiscoveryError::InvalidJson(e.to_string()))?;
    let mut peers = Vec::new();
    let Some(peer_obj) = root.get("Peer").and_then(Value::as_object) else {
        return Ok(peers);
    };
    for peer_value in peer_obj.values() {
        let Some(peer) = peer_value.as_object() else {
            continue;
        };
        let Some(hostname) = peer.get("DNSName").and_then(Value::as_str) else {
            continue;
        };
        let short = short_hostname(hostname);
        if !matches_hostname_prefix(short, &config.hostname_prefix) {
            continue;
        }
        if !config.hostname.is_empty()
            && short == short_hostname(&config.hostname)
        {
            continue;
        }
        if !matches!(peer.get("Online"), Some(Value::Bool(true))) {
            continue;
        }
        peers.push(Peer::new(hostname, GOSSIP_PORT));
    }
    Ok(peers)
}

/// Tailscale discovery with configurable retry/fetch/sleep
/// seams. Retries mirror C: each attempt must yield output that
/// parses as JSON, with `retry_delay` slept between attempts;
/// after `max_retries` failures the result is gracefully
/// `Ok(vec![])`, as is unparseable output at the final parse.
fn discover_tailscale_peers_impl<S, F>(
    sink: &mut S,
    config: &DiscoveryConfig,
    mut fetch_status: F,
    max_retries: u32,
    retry_delay: Duration,
) -> Result<Vec<Peer>, DiscoveryError>
where
    S: PeerSink + ?Sized,
    F: FnMut() -> Option<String>,
{
    if config.hostname_prefix.is_empty() {
        return Err(DiscoveryError::InvalidArgument(
            "hostname_prefix not configured".to_string(),
        ));
    }

    let mut json: Option<String> = None;
    for attempt in 0..max_retries {
        if let Some(candidate) = fetch_status() {
            if serde_json::from_str::<Value>(&candidate).is_ok() {
                json = Some(candidate);
                break;
            }
        }
        if attempt + 1 < max_retries && !retry_delay.is_zero() {
            std::thread::sleep(retry_delay);
        }
    }
    let Some(json) = json else {
        return Ok(Vec::new());
    };

    let peers = match parse_tailscale_status(&json, config) {
        Ok(peers) => peers,
        Err(_) => return Ok(Vec::new()),
    };
    let mut registered = Vec::new();
    for peer in &peers {
        register_peer(sink, peer, &mut registered);
    }
    Ok(registered)
}

/// Tailscale discovery with an injectable status source and the
/// production retry policy (30 attempts, 2s apart); see
/// [`discover_tailscale_peers`]. `fetch_status` returns `None`
/// when the status command fails, like C's
/// `execute_tailscale_status` returning NULL.
pub fn discover_tailscale_peers_with<S, F>(
    sink: &mut S,
    config: &DiscoveryConfig,
    fetch_status: F,
) -> Result<Vec<Peer>, DiscoveryError>
where
    S: PeerSink + ?Sized,
    F: FnMut() -> Option<String>,
{
    discover_tailscale_peers_impl(
        sink,
        config,
        fetch_status,
        TAILSCALE_RETRY_COUNT,
        TAILSCALE_RETRY_DELAY,
    )
}

/// Tailscale discovery, C `discover_tailscale_peers`: obtains
/// the peer list by running `tailscale status --json`, retrying
/// up to [`TAILSCALE_RETRY_COUNT`] times while Tailscale is not
/// ready, then registers the matching online peers (see
/// [`parse_tailscale_status`]). An unavailable Tailscale is a
/// graceful `Ok(vec![])`, never an error.
pub fn discover_tailscale_peers<S: PeerSink + ?Sized>(
    sink: &mut S,
    config: &DiscoveryConfig,
) -> Result<Vec<Peer>, DiscoveryError> {
    discover_tailscale_peers_with(sink, config, execute_tailscale_status)
}

/// Main discovery router, C `discover_peers`: routes on
/// `config.discovery_mode`. `none` and unknown modes discover
/// nothing and succeed.
pub fn discover_peers<S: PeerSink + ?Sized>(
    sink: &mut S,
    config: &DiscoveryConfig,
) -> Result<Vec<Peer>, DiscoveryError> {
    match config.mode() {
        DiscoveryMode::Tailscale => discover_tailscale_peers(sink, config),
        DiscoveryMode::DnsPattern => discover_dns_pattern_peers(sink, config),
        DiscoveryMode::Static => discover_static_peers(sink, config),
        DiscoveryMode::None => Ok(Vec::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Sink whose registrations always fail.
    struct FailingSink;

    impl PeerSink for FailingSink {
        fn add_peer(&mut self, _peer: &Peer) -> Result<(), DiscoveryError> {
            Err(DiscoveryError::Sink("boom".to_string()))
        }
    }

    fn sorted(mut peers: Vec<Peer>) -> Vec<Peer> {
        peers.sort();
        peers
    }

    #[test]
    fn mode_from_string_known_modes() {
        assert_eq!(
            discovery_mode_from_string("tailscale"),
            DiscoveryMode::Tailscale
        );
        assert_eq!(
            discovery_mode_from_string("dns_pattern"),
            DiscoveryMode::DnsPattern
        );
        assert_eq!(discovery_mode_from_string("static"), DiscoveryMode::Static);
        assert_eq!(discovery_mode_from_string("none"), DiscoveryMode::None);
    }

    #[test]
    fn mode_from_string_case_insensitive_with_none_fallback() {
        assert_eq!(
            discovery_mode_from_string("TAILSCALE"),
            DiscoveryMode::Tailscale
        );
        assert_eq!(
            discovery_mode_from_string("Dns_Pattern"),
            DiscoveryMode::DnsPattern
        );
        assert_eq!(discovery_mode_from_string(""), DiscoveryMode::None);
        assert_eq!(discovery_mode_from_string("bogus"), DiscoveryMode::None);
        // C compares the whole string: surrounding space matches nothing.
        assert_eq!(discovery_mode_from_string(" static"), DiscoveryMode::None);
    }

    #[test]
    fn default_config_uses_static_mode() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.discovery_mode, "static");
        assert_eq!(config.mode(), DiscoveryMode::Static);
        assert!(config.peers.is_empty());
    }

    #[test]
    fn parse_peer_string_default_and_explicit_port() {
        assert_eq!(
            parse_peer_string("node2.example.org"),
            Ok(Peer::new("node2.example.org", 9000))
        );
        assert_eq!(
            parse_peer_string("node2.example.org:9001"),
            Ok(Peer::new("node2.example.org", 9001))
        );
        assert_eq!(
            parse_peer_string("192.168.1.10:65535"),
            Ok(Peer::new("192.168.1.10", 65535))
        );
    }

    #[test]
    fn parse_peer_string_rejects_bad_ports() {
        assert!(parse_peer_string("host:0").is_err());
        assert!(parse_peer_string("host:65536").is_err());
        assert!(parse_peer_string("host:-5").is_err());
        assert!(parse_peer_string("host:abc").is_err());
        assert!(parse_peer_string("host:").is_err());
        // Split is at the first colon, so the port text is "b:c".
        assert!(parse_peer_string("a:b:c").is_err());
    }

    #[test]
    fn parse_peer_string_atoi_quirks() {
        // atoi stops at the first non-digit and skips leading space.
        assert_eq!(
            parse_peer_string("host:9000abc"),
            Ok(Peer::new("host", 9000))
        );
        assert_eq!(
            parse_peer_string("host: 9002"),
            Ok(Peer::new("host", 9002))
        );
        assert_eq!(
            parse_peer_string("host:+9003"),
            Ok(Peer::new("host", 9003))
        );
    }

    #[test]
    fn parse_peer_string_hostname_length_limit() {
        let ok_host = "a".repeat(255);
        let long_host = "a".repeat(256);
        assert_eq!(
            parse_peer_string(&ok_host),
            Ok(Peer::new(ok_host.clone(), 9000))
        );
        assert!(parse_peer_string(&long_host).is_err());
        assert!(parse_peer_string(&format!("{long_host}:9000")).is_err());
        // The port part does not count toward the hostname limit.
        assert_eq!(
            parse_peer_string(&format!("{ok_host}:9000")),
            Ok(Peer::new(ok_host, 9000))
        );
    }

    #[test]
    fn parse_peer_string_empty_hostname_like_c() {
        // C's parser does not reject an empty hostname.
        assert_eq!(parse_peer_string(""), Ok(Peer::new("", 9000)));
        assert_eq!(parse_peer_string(":9000"), Ok(Peer::new("", 9000)));
    }

    #[test]
    fn c_atoi_matches_c_semantics() {
        assert_eq!(c_atoi("9000"), 9000);
        assert_eq!(c_atoi("  42"), 42);
        assert_eq!(c_atoi("-5"), -5);
        assert_eq!(c_atoi("+7"), 7);
        assert_eq!(c_atoi("12x34"), 12);
        assert_eq!(c_atoi("x12"), 0);
        assert_eq!(c_atoi(""), 0);
    }

    fn static_config() -> DiscoveryConfig {
        DiscoveryConfig {
            discovery_mode: "static".to_string(),
            hostname: "node1.example.org".to_string(),
            peers: vec![
                "node2.example.org:9001".to_string(),
                "node1.example.org".to_string(),
                "node1.example.org:1234".to_string(),
                "not a peer:xyz".to_string(),
                "node3.example.org".to_string(),
                "node2.example.org:9001".to_string(),
            ],
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn parse_static_peers_filters_self_and_invalid() {
        // Self is skipped by hostname regardless of port, invalid
        // strings are skipped, and duplicates are kept (the sink
        // deduplicates them, as the gossip service does).
        assert_eq!(
            parse_static_peers(&static_config()),
            vec![
                Peer::new("node2.example.org", 9001),
                Peer::new("node3.example.org", 9000),
                Peer::new("node2.example.org", 9001),
            ]
        );
    }

    #[test]
    fn discover_static_peers_registers_and_dedups_in_sink() {
        let mut sink = InMemoryPeerSink::new();
        let registered = discover_static_peers(&mut sink, &static_config())
            .expect("static discovery succeeds");
        // Return value mirrors C's peers_found count (duplicates
        // included); the sink holds the deduplicated set.
        assert_eq!(registered.len(), 3);
        assert_eq!(
            sink.peers(),
            &[
                Peer::new("node2.example.org", 9001),
                Peer::new("node3.example.org", 9000),
            ][..]
        );
    }

    #[test]
    fn discover_static_peers_empty_list_is_ok() {
        let mut sink = InMemoryPeerSink::new();
        let config = DiscoveryConfig::default();
        assert_eq!(discover_static_peers(&mut sink, &config), Ok(vec![]));
        assert!(sink.peers().is_empty());
    }

    #[test]
    fn sink_failure_is_swallowed_like_c() {
        let mut sink = FailingSink;
        assert_eq!(
            discover_static_peers(&mut sink, &static_config()),
            Ok(vec![])
        );
    }

    #[test]
    fn in_memory_sink_dedups_and_caps_like_gossip_service() {
        let mut sink = InMemoryPeerSink::new();
        let peer = Peer::new("node2.example.org", 9000);
        assert!(sink.add_peer(&peer).is_ok());
        assert!(sink.add_peer(&peer).is_ok());
        assert_eq!(sink.peers().len(), 1);
        // Same hostname on another port is a different peer.
        assert!(sink.add_peer(&Peer::new("node2.example.org", 9001)).is_ok());
        assert_eq!(sink.peers().len(), 2);

        let mut full = InMemoryPeerSink::new();
        for i in 0..GOSSIP_MAX_PEERS {
            let p = Peer::new(format!("node{i}.example.org"), 9000);
            assert!(full.add_peer(&p).is_ok());
        }
        // Capacity is checked before dedup, as in C: even an
        // already-known peer is rejected once the table is full.
        let known = Peer::new("node0.example.org", 9000);
        assert!(full.add_peer(&known).is_err());
        let new_peer = Peer::new("extra.example.org", 9000);
        assert!(full.add_peer(&new_peer).is_err());
        assert_eq!(full.peers().len(), GOSSIP_MAX_PEERS);
    }

    fn dns_config() -> DiscoveryConfig {
        DiscoveryConfig {
            discovery_mode: "dns_pattern".to_string(),
            hostname: "tw-node07.duckdns.org".to_string(),
            hostname_prefix: "tw-node".to_string(),
            dns_domain: "duckdns.org".to_string(),
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn dns_candidates_expand_zero_padded_01_to_99() {
        let mut config = dns_config();
        config.hostname = String::new();
        let candidates = dns_pattern_candidates(&config);
        assert_eq!(candidates.len(), 99);
        assert_eq!(candidates[0], "tw-node01.duckdns.org");
        assert_eq!(candidates[8], "tw-node09.duckdns.org");
        assert_eq!(candidates[9], "tw-node10.duckdns.org");
        assert_eq!(candidates[98], "tw-node99.duckdns.org");
        assert!(!candidates.iter().any(|c| c.contains("tw-node00")));
        assert!(!candidates.iter().any(|c| c.contains("tw-node100")));
    }

    #[test]
    fn dns_candidates_exclude_self() {
        let candidates = dns_pattern_candidates(&dns_config());
        assert_eq!(candidates.len(), 98);
        assert!(!candidates.iter().any(|c| c == "tw-node07.duckdns.org"));
        assert!(candidates.iter().any(|c| c == "tw-node06.duckdns.org"));
        assert!(candidates.iter().any(|c| c == "tw-node08.duckdns.org"));
    }

    #[test]
    fn dns_discovery_registers_only_resolving_candidates() {
        let mut sink = InMemoryPeerSink::new();
        let resolving = ["tw-node02.duckdns.org", "tw-node05.duckdns.org"];
        let registered = discover_dns_pattern_peers_with(
            &mut sink,
            &dns_config(),
            |hostname| resolving.contains(&hostname),
        )
        .expect("dns discovery succeeds");
        let expected = vec![
            Peer::new("tw-node02.duckdns.org", 9000),
            Peer::new("tw-node05.duckdns.org", 9000),
        ];
        assert_eq!(registered, expected);
        assert_eq!(sink.peers(), &expected[..]);
    }

    #[test]
    fn dns_discovery_nothing_resolving_is_ok() {
        let mut sink = InMemoryPeerSink::new();
        assert_eq!(
            discover_dns_pattern_peers_with(&mut sink, &dns_config(), |_| false),
            Ok(vec![])
        );
    }

    #[test]
    fn dns_discovery_requires_prefix_and_domain() {
        let mut sink = InMemoryPeerSink::new();
        let mut no_prefix = dns_config();
        no_prefix.hostname_prefix = String::new();
        assert!(matches!(
            discover_dns_pattern_peers_with(&mut sink, &no_prefix, |_| {
                panic!("resolver must not be called")
            }),
            Err(DiscoveryError::InvalidArgument(_))
        ));
        let mut no_domain = dns_config();
        no_domain.dns_domain = String::new();
        assert!(matches!(
            discover_dns_pattern_peers_with(&mut sink, &no_domain, |_| {
                panic!("resolver must not be called")
            }),
            Err(DiscoveryError::InvalidArgument(_))
        ));
    }

    /// Trimmed example of real `tailscale status --json` output.
    const TAILSCALE_STATUS_JSON: &str = r#"{
        "Version": "1.52.1",
        "Self": {
            "DNSName": "tw-node01.tailnet.ts.net",
            "Online": true
        },
        "Peer": {
            "100.64.0.1": { "DNSName": "tw-node01.tailnet.ts.net", "Online": true },
            "100.64.0.2": { "DNSName": "tw-node02.tailnet.ts.net", "Online": true },
            "100.64.0.3": { "DNSName": "tw-node03.tailnet.ts.net", "Online": false },
            "100.64.0.4": { "DNSName": "other-host.tailnet.ts.net", "Online": true },
            "100.64.0.5": { "DNSName": "tw-node05", "Online": true },
            "100.64.0.6": { "Online": true },
            "100.64.0.7": { "DNSName": "tw-node07.tailnet.ts.net" },
            "100.64.0.8": { "DNSName": "tw-node08.tailnet.ts.net", "Online": "yes" },
            "100.64.0.9": "not-an-object"
        }
    }"#;

    fn tailscale_config() -> DiscoveryConfig {
        DiscoveryConfig {
            discovery_mode: "tailscale".to_string(),
            hostname: "tw-node01.tailnet.ts.net".to_string(),
            hostname_prefix: "tw-node".to_string(),
            ..DiscoveryConfig::default()
        }
    }

    #[test]
    fn parse_tailscale_status_filters_peers() {
        // Kept: online, prefix-matching, non-self peers, with the
        // full DNSName preserved. Dropped: self, offline peers,
        // non-matching prefixes, and entries without a string
        // DNSName or a boolean-true Online.
        let peers = parse_tailscale_status(TAILSCALE_STATUS_JSON, &tailscale_config())
            .expect("fixture parses");
        assert_eq!(
            sorted(peers),
            vec![
                Peer::new("tw-node02.tailnet.ts.net", 9000),
                Peer::new("tw-node05", 9000),
            ]
        );
    }

    #[test]
    fn parse_tailscale_status_self_match_uses_short_hostname() {
        // Own hostname configured in short form still skips the
        // FQDN self entry; with no own hostname it is kept.
        let mut short_self = tailscale_config();
        short_self.hostname = "tw-node01".to_string();
        let peers = parse_tailscale_status(TAILSCALE_STATUS_JSON, &short_self)
            .expect("fixture parses");
        assert!(!peers.iter().any(|p| p.hostname.starts_with("tw-node01")));

        let mut no_self = tailscale_config();
        no_self.hostname = String::new();
        let peers = parse_tailscale_status(TAILSCALE_STATUS_JSON, &no_self)
            .expect("fixture parses");
        assert!(peers
            .iter()
            .any(|p| p.hostname == "tw-node01.tailnet.ts.net"));
    }

    #[test]
    fn parse_tailscale_status_prefix_match_is_case_sensitive() {
        let mut config = tailscale_config();
        config.hostname_prefix = "TW-NODE".to_string();
        assert_eq!(
            parse_tailscale_status(TAILSCALE_STATUS_JSON, &config),
            Ok(vec![])
        );
    }

    #[test]
    fn parse_tailscale_status_invalid_json() {
        assert!(matches!(
            parse_tailscale_status("not json", &tailscale_config()),
            Err(DiscoveryError::InvalidJson(_))
        ));
        assert!(matches!(
            parse_tailscale_status("", &tailscale_config()),
            Err(DiscoveryError::InvalidJson(_))
        ));
    }

    #[test]
    fn parse_tailscale_status_missing_peer_object() {
        assert_eq!(
            parse_tailscale_status(r#"{"Self": {}}"#, &tailscale_config()),
            Ok(vec![])
        );
        assert_eq!(
            parse_tailscale_status(r#"{"Peer": []}"#, &tailscale_config()),
            Ok(vec![])
        );
        assert_eq!(
            parse_tailscale_status(r#"{"Peer": {}}"#, &tailscale_config()),
            Ok(vec![])
        );
    }

    #[test]
    fn tailscale_discovery_with_injected_status() {
        let mut sink = InMemoryPeerSink::new();
        let mut calls = 0;
        let registered = discover_tailscale_peers_impl(
            &mut sink,
            &tailscale_config(),
            || {
                calls += 1;
                Some(TAILSCALE_STATUS_JSON.to_string())
            },
            3,
            Duration::ZERO,
        )
        .expect("tailscale discovery succeeds");
        assert_eq!(calls, 1);
        assert_eq!(
            sorted(registered.clone()),
            vec![
                Peer::new("tw-node02.tailnet.ts.net", 9000),
                Peer::new("tw-node05", 9000),
            ]
        );
        assert_eq!(sorted(sink.peers().to_vec()), sorted(registered));
    }

    #[test]
    fn tailscale_discovery_retries_until_valid_json() {
        let mut sink = InMemoryPeerSink::new();
        let mut responses: std::collections::VecDeque<Option<String>> = vec![
            None,
            Some("not json yet".to_string()),
            Some(TAILSCALE_STATUS_JSON.to_string()),
        ]
        .into_iter()
        .collect();
        let mut calls = 0;
        let registered = discover_tailscale_peers_impl(
            &mut sink,
            &tailscale_config(),
            || {
                calls += 1;
                responses.pop_front().unwrap_or(None)
            },
            5,
            Duration::ZERO,
        )
        .expect("tailscale discovery succeeds after retries");
        assert_eq!(calls, 3);
        assert_eq!(registered.len(), 2);
    }

    #[test]
    fn tailscale_discovery_unavailable_is_graceful() {
        let mut sink = InMemoryPeerSink::new();
        let mut calls = 0;
        let registered = discover_tailscale_peers_impl(
            &mut sink,
            &tailscale_config(),
            || {
                calls += 1;
                None
            },
            3,
            Duration::ZERO,
        )
        .expect("unavailable tailscale is not an error");
        assert_eq!(calls, 3);
        assert_eq!(registered, vec![]);
        assert!(sink.peers().is_empty());
    }

    #[test]
    fn tailscale_discovery_requires_hostname_prefix() {
        let mut sink = InMemoryPeerSink::new();
        let mut config = tailscale_config();
        config.hostname_prefix = String::new();
        assert!(matches!(
            discover_tailscale_peers_with(&mut sink, &config, || -> Option<String> {
                panic!("status must not be fetched")
            }),
            Err(DiscoveryError::InvalidArgument(_))
        ));
    }

    #[test]
    fn discover_peers_routes_by_mode() {
        let mut sink = InMemoryPeerSink::new();
        assert_eq!(
            discover_peers(&mut sink, &static_config()),
            Ok(vec![
                Peer::new("node2.example.org", 9001),
                Peer::new("node3.example.org", 9000),
                Peer::new("node2.example.org", 9001),
            ])
        );

        let mut sink = InMemoryPeerSink::new();
        let mut none_config = DiscoveryConfig::default();
        none_config.discovery_mode = "none".to_string();
        assert_eq!(discover_peers(&mut sink, &none_config), Ok(vec![]));
        none_config.discovery_mode = "bogus".to_string();
        assert_eq!(discover_peers(&mut sink, &none_config), Ok(vec![]));

        // Backend argument errors propagate through the router.
        let mut sink = InMemoryPeerSink::new();
        let mut dns = dns_config();
        dns.dns_domain = String::new();
        assert!(matches!(
            discover_peers(&mut sink, &dns),
            Err(DiscoveryError::InvalidArgument(_))
        ));
        let mut tailscale = tailscale_config();
        tailscale.hostname_prefix = String::new();
        assert!(matches!(
            discover_peers(&mut sink, &tailscale),
            Err(DiscoveryError::InvalidArgument(_))
        ));
    }

    #[test]
    fn network_config_json_nested_format() {
        let json = r#"{
            "nodes": [
                { "id": "node_01", "hostname": "tw-node01.example.org",
                  "peers": ["tw-node02.example.org:9000", 42, "tw-node03.example.org"] },
                { "id": "node_02", "hostname": "tw-node02.example.org", "peers": [] }
            ],
            "docker": { "discovery": {
                "mode": "dns_pattern",
                "hostname_prefix": "tw-node",
                "dns_pattern": { "domain": "example.org" }
            } }
        }"#;
        let config = DiscoveryConfig::from_network_config_json(json, "node_01")
            .expect("nested config parses");
        assert_eq!(config.discovery_mode, "dns_pattern");
        assert_eq!(config.hostname, "tw-node01.example.org");
        assert_eq!(config.hostname_prefix, "tw-node");
        assert_eq!(config.dns_domain, "example.org");
        // Non-string peer entries are dropped, as the C static
        // backend skips the NULL entries cJSON leaves behind.
        assert_eq!(
            config.peers,
            vec![
                "tw-node02.example.org:9000".to_string(),
                "tw-node03.example.org".to_string(),
            ]
        );
        assert!(matches!(
            DiscoveryConfig::from_network_config_json(json, "node_99"),
            Err(DiscoveryError::InvalidArgument(_))
        ));
    }

    #[test]
    fn network_config_json_flat_format() {
        let json = r#"{
            "id": "node_01",
            "hostname": "tw-node01.example.org",
            "peers": ["tw-node02.example.org"],
            "docker": { "discovery": { "mode": "static" } }
        }"#;
        let config = DiscoveryConfig::from_network_config_json(json, "node_01")
            .expect("flat config parses");
        assert_eq!(config.hostname, "tw-node01.example.org");
        assert_eq!(config.peers, vec!["tw-node02.example.org".to_string()]);
        assert!(matches!(
            DiscoveryConfig::from_network_config_json(json, "node_02"),
            Err(DiscoveryError::InvalidArgument(_))
        ));
        assert!(matches!(
            DiscoveryConfig::from_network_config_json("nope", "node_01"),
            Err(DiscoveryError::InvalidJson(_))
        ));
    }

    #[test]
    fn hostname_helpers_match_c() {
        assert_eq!(short_hostname("tw-node01.tailnet.ts.net"), "tw-node01");
        assert_eq!(short_hostname("tw-node01"), "tw-node01");
        assert_eq!(short_hostname(""), "");

        assert!(matches_hostname_prefix("tw-node01", "tw-node"));
        assert!(matches_hostname_prefix("tw-node01", "tw-node01"));
        assert!(!matches_hostname_prefix("tw-node01", ""));
        assert!(!matches_hostname_prefix("TW-node01", "tw-"));
        assert!(!matches_hostname_prefix("tw", "tw-node"));

        assert_eq!(extract_node_index("tw_node01", "tw_node"), Some(1));
        assert_eq!(extract_node_index("tw_node99", "tw_node"), Some(99));
        assert_eq!(extract_node_index("tw_node00", "tw_node"), Some(0));
        assert_eq!(extract_node_index("tw_node1", "tw_node"), None);
        assert_eq!(extract_node_index("tw_node012", "tw_node"), None);
        assert_eq!(extract_node_index("tw_node0a", "tw_node"), None);
        assert_eq!(extract_node_index("other01", "tw_node"), None);
    }
}







