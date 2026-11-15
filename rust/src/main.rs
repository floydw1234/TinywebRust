//! TinyWeb (Rust port) — binary entry point.
//!
//! Startup wiring mirroring the C node's `src/main.c`: argument
//! parsing, config (defaults + `TINYWEB_*` environment
//! overrides), state paths, store/keystore initialisation,
//! envelope dispatcher init (inside the gossip ingest pipeline),
//! discovery, gossip service start with the `main.c` ingest
//! handlers, node announcement, HTTP API start, and
//! signal-driven clean shutdown.
//!
//! Simplification versus C, as sanctioned for this port: the
//! database-backed node-config layer (`nodes_get_by_id` /
//! `nodes_insert_or_update` in `main.c`, populated during C
//! initialisation) is not replayed — configuration here is
//! defaults, then environment, then command-line flags, which
//! are also the layers an operator can actually observe. The
//! `nodes` table itself is still created by the store schema.

pub mod api;
pub mod discovery;
pub mod encryption;
pub mod events;
pub mod gossip;
pub mod identity;
pub mod keystore;
pub mod proto;
pub mod sessions;
pub mod store;
pub mod validation;

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey};
use prost::Message as _;

use discovery::{discover_peers, DiscoveryConfig};
use gossip::GossipService;
use proto::{Envelope, EnvelopeHeader, NodeRegistration};
use sha2::{Digest, Sha256};
use store::Store;
use validation::GossipValidationConfig;

// ---------------------------------------------------------------------------
// Config (`config.c`: defaults + `config_load_from_env`)
// ---------------------------------------------------------------------------

/// Node configuration: the subset of C `NodeConfig` this binary
/// consumes (validation limits, ports, identity, discovery).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeConfig {
    pub node_id: String,
    pub node_name: String,
    pub hostname: String,
    pub gossip_port: u16,
    pub api_port: u16,
    pub discovery_mode: String,
    pub hostname_prefix: String,
    pub dns_domain: String,
    pub max_clock_skew_seconds: u64,
    pub message_ttl_seconds: u64,
    pub max_payload_bytes: usize,
    pub debug_mode: bool,
    pub log_level: String,
}

impl Default for NodeConfig {
    /// C `config_set_defaults` (ports/node id filled in later,
    /// as in C `parse_arguments` / `load_node_config`).
    fn default() -> Self {
        NodeConfig {
            node_id: "node_01".to_string(),
            node_name: String::new(),
            hostname: String::new(),
            gossip_port: 9000,
            api_port: 8000,
            discovery_mode: "static".to_string(),
            hostname_prefix: String::new(),
            dns_domain: String::new(),
            max_clock_skew_seconds: 300,
            message_ttl_seconds: 60 * 60 * 24 * 30,
            max_payload_bytes: 1024 * 1024,
            debug_mode: false,
            log_level: "INFO".to_string(),
        }
    }
}

impl NodeConfig {
    fn validation_config(&self) -> GossipValidationConfig {
        GossipValidationConfig {
            max_clock_skew_seconds: self.max_clock_skew_seconds,
            message_ttl_seconds: self.message_ttl_seconds,
            max_payload_bytes: self.max_payload_bytes,
        }
    }

    /// C `config_validate`: ports in range, non-zero limits.
    fn validate(&self) -> Result<(), String> {
        if !(1024..=65535).contains(&self.gossip_port) {
            return Err(format!(
                "Invalid gossip_port: {} (must be 1024-65535)",
                self.gossip_port
            ));
        }
        if !(1024..=65535).contains(&self.api_port) {
            return Err(format!(
                "Invalid api_port: {} (must be 1024-65535)",
                self.api_port
            ));
        }
        if self.max_clock_skew_seconds == 0 {
            return Err("max_clock_skew_seconds must be > 0".to_string());
        }
        if self.message_ttl_seconds == 0 {
            return Err("message_ttl_seconds must be > 0".to_string());
        }
        if self.max_payload_bytes == 0 {
            return Err("max_payload_bytes must be > 0".to_string());
        }
        Ok(())
    }
}

/// Apply the `TINYWEB_*` environment overrides (C
/// `config_load_from_env` merged by `config_merge`: only
/// non-empty / non-zero values override).
pub fn apply_env_overrides(config: &mut NodeConfig) {
    if let Ok(v) = std::env::var("TINYWEB_NODE_ID") {
        if !v.is_empty() {
            // Numeric ids take the `node_%02u` shape of C
            // `load_node_config`; anything else is used verbatim,
            // as the raw string merge in C does.
            match v.parse::<u32>() {
                Ok(n) if n > 0 => config.node_id = format!("node_{n:02}"),
                Ok(_) => {}
                Err(_) => config.node_id = v,
            }
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_GOSSIP_PORT") {
        if let Ok(p) = v.parse::<u16>() {
            if p != 0 {
                config.gossip_port = p;
            }
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_API_PORT") {
        if let Ok(p) = v.parse::<u16>() {
            if p != 0 {
                config.api_port = p;
            }
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_DISCOVERY_MODE") {
        if !v.is_empty() {
            config.discovery_mode = v;
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_HOSTNAME_PREFIX") {
        if !v.is_empty() {
            config.hostname_prefix = v;
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_DNS_DOMAIN") {
        if !v.is_empty() {
            config.dns_domain = v;
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_MAX_CLOCK_SKEW") {
        if let Ok(n) = v.parse::<u64>() {
            if n != 0 {
                config.max_clock_skew_seconds = n;
            }
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_MESSAGE_TTL") {
        if let Ok(n) = v.parse::<u64>() {
            if n != 0 {
                config.message_ttl_seconds = n;
            }
        }
    }
    if let Ok(v) = std::env::var("TINYWEB_DEBUG") {
        config.debug_mode = v.parse::<i64>().map(|n| n != 0).unwrap_or(false);
    }
    if let Ok(v) = std::env::var("TINYWEB_LOG_LEVEL") {
        if v.eq_ignore_ascii_case("ERROR") {
            config.log_level = "ERROR".to_string();
        } else if v.eq_ignore_ascii_case("INFO") {
            config.log_level = "INFO".to_string();
        }
    }
}

// ---------------------------------------------------------------------------
// Argument parsing (`parse_arguments` in main.c)
// ---------------------------------------------------------------------------

/// Outcome of parsing: run with this config, or `--help` was shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseResult {
    Run(NodeConfig),
    Help,
}

fn print_usage(program: &str) {
    println!("Usage: {program} [OPTIONS]");
    println!("Options:");
    println!("  -i, --id <node_id>       Node identifier (default: 0)");
    println!("  -g, --gossip-port <port> Gossip UDP port (default: 9000)");
    println!("  -p, --api-port <port>    HTTP API port (default: 8000)");
    println!("  -d, --debug              Enable debug logging");
    println!("  -h, --help               Show this help message");
    println!();
    println!("Subcommands:");
    println!("  bootstrap-founder [--name <display name>] [--label <device label>]");
    println!("                           Set up the founding member + first device +");
    println!("                           backup-card recovery key on an empty node");
    println!("                           (setup-time only; refuses once a member exists)");
}

/// Parse C-style flags over `config` (already carrying defaults
/// and environment overrides; command-line values win). Both
/// short and long forms are accepted, exactly as in C.
pub fn parse_args(args: &[String], mut config: NodeConfig) -> Result<ParseResult, String> {
    let mut node_id: u32 = 0;
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];
        match arg.as_str() {
            "-i" | "--id" => {
                let Some(value) = args.get(i + 1) else {
                    return Err(format!("Unknown option: {arg}"));
                };
                // C `atoi`: a non-numeric value reads as 0.
                node_id = value.parse::<u32>().unwrap_or(0);
                i += 2;
            }
            "-g" | "--gossip-port" => {
                let Some(value) = args.get(i + 1) else {
                    return Err(format!("Unknown option: {arg}"));
                };
                let port: u32 = value.parse().unwrap_or(0);
                if !(1024..=65535).contains(&port) {
                    return Err("gossip port must be between 1024 and 65535".to_string());
                }
                config.gossip_port = port as u16;
                i += 2;
            }
            "-p" | "--api-port" => {
                let Some(value) = args.get(i + 1) else {
                    return Err(format!("Unknown option: {arg}"));
                };
                let port: u32 = value.parse().unwrap_or(0);
                if !(1024..=65535).contains(&port) {
                    return Err("API port must be between 1024 and 65535".to_string());
                }
                config.api_port = port as u16;
                i += 2;
            }
            "-d" | "--debug" => {
                config.debug_mode = true;
                i += 1;
            }
            "-h" | "--help" => return Ok(ParseResult::Help),
            _ => return Err(format!("Unknown option: {arg}")),
        }
    }
    if node_id > 0 {
        config.node_id = format!("node_{node_id:02}");
    }
    if config.gossip_port == 0 {
        config.gossip_port = 9000;
    }
    if config.api_port == 0 {
        config.api_port = 8000;
    }
    Ok(ParseResult::Run(config))
}

// ---------------------------------------------------------------------------
// State paths (`statePaths.c`, relative to the working directory)
// ---------------------------------------------------------------------------

/// `state/storage/tinyweb.db`
pub fn database_path() -> PathBuf {
    PathBuf::from("state/storage/tinyweb.db")
}

/// `state/keys/node_private.key`
pub fn private_key_path() -> PathBuf {
    PathBuf::from("state/keys/node_private.key")
}

/// Create `state/`, `state/storage/` and `state/keys/`
/// (C `state_paths_ensure_directories`).
pub fn ensure_state_directories() -> std::io::Result<()> {
    std::fs::create_dir_all("state/storage")?;
    std::fs::create_dir_all("state/keys")?;
    Ok(())
}

fn now_epoch() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Founding bootstrap (`bootstrap-founder`, Phase B3)
// ---------------------------------------------------------------------------

/// The credentials a founding bootstrap creates. The private
/// halves exist only in this struct and in the one printout the
/// CLI makes from it — the node stores public keys, the device
/// certificate, and the recovery *pubkey* only. Whoever runs the
/// bootstrap moves the member/device secrets onto the founding
/// phone and prints the recovery secret as the backup card.
pub struct FounderBootstrap {
    pub display_name: String,
    pub device_label: String,
    pub member_pubkey: [u8; 32],
    /// 64-byte keypair bytes (seed || pubkey), as the keystore
    /// returns them; the seed half is what a client rebuilds
    /// its signing key from.
    pub member_secret: [u8; 64],
    pub device_pubkey: [u8; 32],
    pub device_secret: [u8; 64],
    pub recovery_pubkey: [u8; 32],
    pub recovery_secret: [u8; 64],
}

/// Create the founding member, their first device, and the
/// household recovery approver directly in `store`
/// (DESIGN.md §3.2 first-boot: the setup path is the
/// authorization, so this is a CLI, never an HTTP endpoint).
/// Refuses when the household already has any member — after
/// the founder exists, every join goes through the pairing
/// flow with an approver's signature.
pub fn bootstrap_founder_in_store(
    store: &Store,
    display_name: &str,
    device_label: &str,
    now: u64,
) -> Result<FounderBootstrap, String> {
    let count = store.user_count().map_err(|e| e.to_string())?;
    if count > 0 {
        return Err(format!(
            "household already has {count} member(s); founding bootstrap only runs on an empty node"
        ));
    }
    let mut member = keystore::MemberKeystore::new();
    member.generate_member_key().map_err(|e| e.to_string())?;
    let device_pubkey = member.add_device_key(device_label).map_err(|e| e.to_string())?;
    let member_pubkey = member.member_public_key().map_err(|e| e.to_string())?;
    let cert = identity::issue_device_certificate(&member, device_label, now, 0)
        .map_err(|e| e.to_string())?;
    let mut recovery = keystore::Keystore::new();
    recovery.generate_keypair().map_err(|e| e.to_string())?;
    let recovery_pubkey = recovery.get_public_key().map_err(|e| e.to_string())?;

    store
        .user_register(&member_pubkey, display_name)
        .map_err(|e| e.to_string())?;
    store.device_add(&cert, now).map_err(|e| e.to_string())?;
    store
        .recovery_approver_add(&recovery_pubkey, "backup card", now)
        .map_err(|e| e.to_string())?;
    let cert_hash: [u8; 32] = Sha256::digest(cert.encode_to_vec()).into();
    store
        .enrollment_insert(&store::EnrollmentRecord {
            id: 0,
            member_pubkey,
            device_pubkey,
            cert_hash,
            approver_kind: "founder".to_string(),
            approver_member_pubkey: None,
            approver_device_pubkey: None,
            recovery_pubkey: None,
            approval_signature: Vec::new(),
            approval_timestamp: now,
            created_at: now,
        })
        .map_err(|e| e.to_string())?;

    let member_secret = member
        .member_keystore()
        .get_private_key()
        .map_err(|e| e.to_string())?;
    let device_secret = member
        .device_keystore(device_label)
        .ok_or_else(|| "device keystore missing after generation".to_string())?
        .get_private_key()
        .map_err(|e| e.to_string())?;
    let recovery_secret = recovery.get_private_key().map_err(|e| e.to_string())?;
    Ok(FounderBootstrap {
        display_name: display_name.to_string(),
        device_label: device_label.to_string(),
        member_pubkey,
        member_secret,
        device_pubkey,
        device_secret,
        recovery_pubkey,
        recovery_secret,
    })
}

/// `tinyweb bootstrap-founder [--name N] [--label L]`: the
/// setup-time-only founding path. Runs against the same
/// `state/storage/tinyweb.db` the node serves (run it from the
/// node's home directory, with the node stopped or running —
/// the store is WAL and the write is one short burst).
fn bootstrap_founder(args: &[String]) -> i32 {
    let mut name = "Founder".to_string();
    let mut label = "phone".to_string();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--name" => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("error: --name needs a value");
                    return 1;
                };
                name = value.clone();
                i += 2;
            }
            "--label" => {
                let Some(value) = args.get(i + 1) else {
                    eprintln!("error: --label needs a value");
                    return 1;
                };
                label = value.clone();
                i += 2;
            }
            "-h" | "--help" => {
                println!("Usage: tinyweb bootstrap-founder [--name <display name>] [--label <device label>]");
                println!("Creates the founding member, their first device, and the backup-card");
                println!("recovery key on an empty node. Prints the secrets ONCE; the node");
                println!("stores only public keys. Refuses if any member already exists.");
                return 0;
            }
            other => {
                eprintln!("error: unknown bootstrap option: {other}");
                return 1;
            }
        }
    }
    if let Err(e) = ensure_state_directories() {
        eprintln!("error: failed to create state directories: {e}");
        return 1;
    }
    let db_path = database_path();
    let store = match Store::open(&db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "error: failed to open database at {}: {e}",
                db_path.display()
            );
            return 1;
        }
    };
    if let Err(e) = store.init_schema() {
        eprintln!("error: failed to initialise store schema: {e}");
        return 1;
    }
    let boot = match bootstrap_founder_in_store(&store, &name, &label, now_epoch()) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("error: founding bootstrap refused: {e}");
            return 1;
        }
    };
    println!("=================================================================");
    println!("FOUNDING MEMBER CREATED");
    println!("The secrets below are shown ONCE and are not stored on this node.");
    println!("Move the member + device secrets onto the founding phone now.");
    println!("=================================================================");
    println!("Display name:          {}", boot.display_name);
    println!("Member pubkey:         {}", hex_encode(&boot.member_pubkey));
    println!(
        "Member secret (seed):  {}",
        hex_encode(&boot.member_secret[..32])
    );
    println!("Device label:          {}", boot.device_label);
    println!("Device pubkey:         {}", hex_encode(&boot.device_pubkey));
    println!(
        "Device secret (seed):  {}",
        hex_encode(&boot.device_secret[..32])
    );
    println!("-----------------------------------------------------------------");
    println!("BACKUP CARD — print this and keep it in the box:");
    println!("Recovery pubkey:       {}", hex_encode(&boot.recovery_pubkey));
    println!(
        "Recovery secret (seed): {}",
        hex_encode(&boot.recovery_secret[..32])
    );
    println!("The recovery secret can approve a replacement phone or member");
    println!("even if every phone is lost. Anyone holding it can approve a");
    println!("join — keep the card somewhere safe.");
    println!("=================================================================");
    0
}

// ---------------------------------------------------------------------------
// Node announcement (`send_node_announcement` in main.c)
// ---------------------------------------------------------------------------

/// Build, encrypt (for self, as in C), sign and broadcast the
/// `NodeRegistration` announcement. Only called when a node key
/// is loaded; failures are non-fatal in C and here.
fn send_node_announcement(
    service: &GossipService,
    config: &NodeConfig,
) -> Result<(), String> {
    let node_pubkey = keystore::keystore_get_public_key()
        .map_err(|e| format!("failed to get node public key: {e}"))?;
    let node_address = if !config.hostname.is_empty() {
        config.hostname.clone()
    } else if !config.node_id.is_empty() {
        config.node_id.clone()
    } else {
        "unknown".to_string()
    };
    let registration = NodeRegistration {
        node_pubkey: node_pubkey.to_vec(),
        node_address: node_address.clone(),
        node_port: config.gossip_port as u32,
        api_port: config.api_port as u32,
        node_version: "1.0".to_string(),
        stake_proof: Vec::new(),
    };
    let content = registration.encode_to_vec();
    let mut envelope = Envelope {
        header: Some(EnvelopeHeader {
            version: 1,
            content_type: gossip::CONTENT_NODE_REGISTRATION,
            schema_version: 1,
            timestamp: now_epoch(),
            sender_pubkey: node_pubkey.to_vec(),
            recipients_pubkey: vec![node_pubkey.to_vec()],
            group_id: Vec::new(),
        }),
        payload_nonce: Vec::new(),
        ephemeral_pubkey: Vec::new(),
        payload_ciphertext: Vec::new(),
        keywraps: Vec::new(),
        signature: Vec::new(),
    };
    encryption::encrypt_envelope_payload_global(&content, &[node_pubkey], &mut envelope)
        .map_err(|e| format!("failed to encrypt node announcement: {e}"))?;
    let digest = validation::compute_envelope_signing_digest(&envelope)
        .ok_or_else(|| "failed to compute announcement digest".to_string())?;
    let secret = keystore::keystore_get_private_key()
        .map_err(|e| format!("failed to get node private key: {e}"))?;
    // libsodium secret keys are seed||pubkey; the seed signs.
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&secret[..32]);
    let signing = SigningKey::from_bytes(&seed);
    envelope.signature = signing.sign(&digest).to_bytes().to_vec();
    service
        .broadcast_envelope(&envelope)
        .map_err(|e| format!("failed to broadcast node announcement: {e}"))?;
    println!(
        "Sent node announcement: {} (port {})",
        node_address, config.gossip_port
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Signals (C `handle_signal` on SIGINT/SIGTERM)
// ---------------------------------------------------------------------------

static RUNNING: AtomicBool = AtomicBool::new(true);

extern "C" fn handle_signal(_sig: i32) {
    RUNNING.store(false, Ordering::SeqCst);
}

type SigHandler = extern "C" fn(i32);
extern "C" {
    fn signal(signum: i32, handler: SigHandler) -> SigHandler;
}

fn install_signal_handlers() {
    // SIGINT = 2, SIGTERM = 15 (Linux, as targeted by the C build).
    unsafe {
        signal(2, handle_signal);
        signal(15, handle_signal);
    }
}

// ---------------------------------------------------------------------------
// Startup (`main` in main.c)
// ---------------------------------------------------------------------------

fn run() -> i32 {
    let argv: Vec<String> = std::env::args().collect();
    let program = argv.first().cloned().unwrap_or_else(|| "tinyweb".to_string());

    // Setup-time subcommand (Phase B3 founding bootstrap): not
    // a node flag, and it must not fall through to the C-style
    // flag parser below.
    if argv.get(1).map(|s| s.as_str()) == Some("bootstrap-founder") {
        return bootstrap_founder(&argv[2.min(argv.len())..]);
    }

    let mut config = NodeConfig::default();
    apply_env_overrides(&mut config);
    let config = match parse_args(&argv[1.min(argv.len())..], config) {
        Ok(ParseResult::Run(c)) => c,
        Ok(ParseResult::Help) => {
            print_usage(&program);
            return 0;
        }
        Err(e) => {
            eprintln!("error: {e}");
            print_usage(&program);
            return 1;
        }
    };
    if let Err(e) = config.validate() {
        eprintln!("error: configuration validation failed: {e}");
        return 1;
    }
    let validation_config = config.validation_config();

    install_signal_handlers();

    // State paths + store (`initialize_storage`).
    if let Err(e) = ensure_state_directories() {
        eprintln!("error: failed to create state directories: {e}");
        return 1;
    }
    let db_path = database_path();
    let store = match Store::open(&db_path) {
        Ok(s) => match s.init_schema() {
            Ok(()) => Arc::new(Mutex::new(s)),
            Err(e) => {
                eprintln!("error: failed to initialise store schema: {e}");
                return 1;
            }
        },
        Err(e) => {
            eprintln!(
                "error: failed to initialise database at {}: {e}",
                db_path.display()
            );
            return 1;
        }
    };

    // Keystore + raw node key (`keystore_init` + the key-file
    // load in main.c: a missing key disables announcements but
    // the node still runs).
    if let Err(e) = keystore::keystore_init() {
        eprintln!("error: failed to initialise keystore: {e}");
        return 1;
    }
    let key_path = private_key_path();
    let mut key_loaded = false;
    match std::fs::read(&key_path) {
        Ok(bytes) => {
            if bytes.len() == 64 {
                let mut secret = [0u8; 64];
                secret.copy_from_slice(&bytes);
                match keystore::keystore_load_raw_ed25519_keypair(&secret) {
                    Ok(()) => {
                        println!("Loaded node keypair from {}", key_path.display());
                        key_loaded = true;
                    }
                    Err(e) => {
                        eprintln!(
                            "error: failed to load node keypair from {}: {e}",
                            key_path.display()
                        );
                    }
                }
            } else {
                eprintln!(
                    "error: invalid key file size in {} (got {}, expected 64)",
                    key_path.display(),
                    bytes.len()
                );
            }
        }
        Err(_) => {
            println!(
                "No node keypair found at {} (node announcements disabled)",
                key_path.display()
            );
        }
    }

    // Gossip service with the `main.c` ingest handlers; attaching
    // the ingest pipeline also initialises the envelope
    // dispatcher with its default content handlers (C
    // `envelope_dispatcher_init`).
    let decryptor: gossip::EnvelopeDecryptor = Arc::new(|envelope| {
        encryption::decrypt_envelope_payload_global(envelope).ok()
    });
    let mut service = GossipService::new(config.gossip_port, None, None);
    let _pipeline = service.attach_ingest(
        store.clone(),
        validation_config,
        Some(decryptor),
    );
    let service = Arc::new(Mutex::new(service));
    {
        let mut svc = service.lock().unwrap();
        if let Err(e) = svc.start() {
            eprintln!("error: failed to start gossip service: {e}");
            return 1;
        }
    }

    // Discovery (C `discover_peers` inside `start_gossip_service`,
    // mode from config, default static). For static mode C first
    // loads DB peers into `config->peers`, skipping self.
    {
        let mut peers: Vec<String> = Vec::new();
        if config.discovery_mode.eq_ignore_ascii_case("static") {
            let db_peers = {
                let s = store.lock().unwrap();
                s.gossip_peers_fetch_all()
            };
            if let Ok(db_peers) = db_peers {
                for peer in &db_peers {
                    if peer.hostname.is_empty() || peer.gossip_port == 0 {
                        continue;
                    }
                    if !config.hostname.is_empty() && peer.hostname == config.hostname {
                        continue;
                    }
                    peers.push(format!("{}:{}", peer.hostname, peer.gossip_port));
                }
            }
        }
        let discovery_config = DiscoveryConfig {
            discovery_mode: config.discovery_mode.clone(),
            hostname: config.hostname.clone(),
            hostname_prefix: config.hostname_prefix.clone(),
            dns_domain: config.dns_domain.clone(),
            peers,
        };
        let mut sink = {
            let svc = service.lock().unwrap();
            svc.peer_sink(Some(store.clone()))
        };
        match discover_peers(&mut sink, &discovery_config) {
            Ok(found) => {
                if !found.is_empty() {
                    println!("Discovery found {} peer(s)", found.len());
                }
            }
            Err(e) => {
                // Non-fatal in C: fall back to database peers only.
                println!("Discovery failed ({e}), falling back to database peers only");
            }
        }
    }

    // Bootstrap known peers from the database (C
    // `bootstrap_known_peers`).
    {
        let db_peers = {
            let s = store.lock().unwrap();
            s.gossip_peers_fetch_all()
        };
        if let Ok(db_peers) = db_peers {
            let svc = service.lock().unwrap();
            let mut added = 0usize;
            for peer in &db_peers {
                if peer.hostname.is_empty() || peer.gossip_port == 0 {
                    continue;
                }
                if svc.add_peer(&peer.hostname, peer.gossip_port).is_ok() {
                    added += 1;
                }
            }
            if added > 0 {
                println!("Loaded {added} bootstrap peers from database");
            }
        }
    }

    // Node announcement (only with a loaded key, as in C).
    if key_loaded {
        let svc = service.lock().unwrap();
        if let Err(e) = send_node_announcement(&svc, &config) {
            println!("Failed to send node announcement (non-fatal): {e}");
        }
    }

    // Expired-row cleanup loop (C `cleanup_loop`, every 60s).
    let cleanup_running = Arc::new(AtomicBool::new(true));
    let cleanup_thread = {
        let cleanup_running = cleanup_running.clone();
        let cleanup_store = store.clone();
        std::thread::spawn(move || {
            let mut waited = 0u32;
            while cleanup_running.load(Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_secs(1));
                waited += 1;
                if waited >= 60 {
                    waited = 0;
                    let s = cleanup_store.lock().unwrap();
                    let _ = s.gossip_store_cleanup(now_epoch());
                }
            }
        })
    };

    // HTTP API (C `start_http_api` / `gossip_api_start`).
    let api_state = api::ApiState::new(
        store.clone(),
        Some(service.clone()),
        validation_config,
    );
    let mut api_server = match api::ApiServer::start(config.api_port, api_state) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: failed to start HTTP API on port {}: {e}", config.api_port);
            cleanup_running.store(false, Ordering::SeqCst);
            let _ = cleanup_thread.join();
            service.lock().unwrap().stop();
            return 1;
        }
    };

    println!("=================================================================");
    println!("TinyWeb Gossip Node Online");
    println!("=================================================================");
    println!("  Node ID:           {}", config.node_id);
    println!("  Node Name:         {}", config.node_name);
    println!("  Gossip UDP Port:   {}", config.gossip_port);
    println!("  HTTP API Port:     {}", config.api_port);
    println!("  Storage Path:      {}", db_path.display());
    println!("-----------------------------------------------------------------");
    println!("Waiting for gossip traffic... Press Ctrl+C to exit.");

    while RUNNING.load(Ordering::SeqCst) {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    println!("\nReceived shutdown signal. Stopping services...");
    api_server.stop();
    cleanup_running.store(false, Ordering::SeqCst);
    let _ = cleanup_thread.join();
    service.lock().unwrap().stop();
    keystore::keystore_cleanup();
    {
        let s = store.lock().unwrap();
        let _ = s.gossip_store_cleanup(now_epoch());
    }
    println!("Shutdown complete. Goodbye!");
    0
}

fn main() {
    std::process::exit(run());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn defaults_are_c_defaults() {
        let cfg = match parse_args(&args(&[]), NodeConfig::default()).unwrap() {
            ParseResult::Run(c) => c,
            ParseResult::Help => panic!("unexpected help"),
        };
        assert_eq!(cfg.node_id, "node_01");
        assert_eq!(cfg.gossip_port, 9000);
        assert_eq!(cfg.api_port, 8000);
        assert_eq!(cfg.discovery_mode, "static");
        assert!(!cfg.debug_mode);
    }

    #[test]
    fn short_and_long_flags() {
        let cfg = match parse_args(
            &args(&["--id", "1", "--gossip-port", "9001", "--api-port", "8001", "--debug"]),
            NodeConfig::default(),
        )
        .unwrap()
        {
            ParseResult::Run(c) => c,
            ParseResult::Help => panic!("unexpected help"),
        };
        assert_eq!(cfg.node_id, "node_01");
        assert_eq!(cfg.gossip_port, 9001);
        assert_eq!(cfg.api_port, 8001);
        assert!(cfg.debug_mode);

        let cfg = match parse_args(
            &args(&["-i", "12", "-g", "9100", "-p", "8100", "-d"]),
            NodeConfig::default(),
        )
        .unwrap()
        {
            ParseResult::Run(c) => c,
            ParseResult::Help => panic!("unexpected help"),
        };
        assert_eq!(cfg.node_id, "node_12");
        assert_eq!(cfg.gossip_port, 9100);
        assert_eq!(cfg.api_port, 8100);
        assert!(cfg.debug_mode);
    }

    #[test]
    fn help_and_errors() {
        assert_eq!(
            parse_args(&args(&["-h"]), NodeConfig::default()).unwrap(),
            ParseResult::Help
        );
        assert_eq!(
            parse_args(&args(&["--help"]), NodeConfig::default()).unwrap(),
            ParseResult::Help
        );
        assert!(parse_args(&args(&["--bogus"]), NodeConfig::default()).is_err());
        assert!(parse_args(&args(&["-g"]), NodeConfig::default()).is_err());
        assert!(parse_args(&args(&["-g", "80"]), NodeConfig::default()).is_err());
        assert!(parse_args(&args(&["-p", "70000"]), NodeConfig::default()).is_err());
        // id 0 keeps the default node_01, as in C.
        let cfg = match parse_args(&args(&["-i", "0"]), NodeConfig::default()).unwrap() {
            ParseResult::Run(c) => c,
            ParseResult::Help => panic!("unexpected help"),
        };
        assert_eq!(cfg.node_id, "node_01");
    }

    #[test]
    fn config_validation_rejects_bad_limits() {
        let mut cfg = NodeConfig::default();
        assert!(cfg.validate().is_ok());
        cfg.max_clock_skew_seconds = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn bootstrap_founder_creates_founder_and_refuses_a_second_run() {
        let store = Store::open_in_memory().unwrap();
        store.init_schema().unwrap();
        let now = 1_700_000_000;
        let boot = bootstrap_founder_in_store(&store, "Founder", "phone", now).unwrap();
        // The founder is fully enrolled: active member, trusted
        // device, recovery key registered, audit record written.
        assert!(store.user_exists(&boot.member_pubkey));
        assert!(store
            .device_is_trusted(&boot.member_pubkey, &boot.device_pubkey, now)
            .unwrap());
        assert!(store
            .recovery_approver_is_registered(&boot.recovery_pubkey)
            .unwrap());
        let enrollments = store.enrollments_for_member(&boot.member_pubkey).unwrap();
        assert_eq!(enrollments.len(), 1);
        assert_eq!(enrollments[0].approver_kind, "founder");
        assert!(enrollments[0].approval_signature.is_empty());
        // The returned secrets correspond to the stored pubkeys
        // (seed || pubkey keypair bytes).
        assert_eq!(&boot.member_secret[32..], &boot.member_pubkey[..]);
        assert_eq!(&boot.device_secret[32..], &boot.device_pubkey[..]);
        assert_eq!(&boot.recovery_secret[32..], &boot.recovery_pubkey[..]);
        // A second bootstrap is refused and changes nothing.
        let again = bootstrap_founder_in_store(&store, "Second", "phone", now);
        assert!(again.is_err());
        assert_eq!(store.user_count().unwrap(), 1);
    }
}
