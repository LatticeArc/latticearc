//! Keystore management commands.
//!
//! Provides CLI commands for creating, opening, and managing an encrypted
//! keystore protected by a master password.

use anyhow::{Context, Result, bail};
use clap::{Args, Subcommand};
use std::path::PathBuf;
use zeroize::Zeroizing;

use crate::keyfile::{KeyFile, KeyType};
use crate::keystore::{KeyStore, StoredKeyType};

/// Arguments for the `keystore` subcommand.
#[derive(Args)]
pub(crate) struct KeystoreArgs {
    /// Keystore directory (defaults to ~/.latticearc/keys/).
    #[arg(long, global = true)]
    pub store_dir: Option<PathBuf>,
    /// Subcommand.
    #[command(subcommand)]
    pub command: KeystoreCommand,
}

/// Keystore subcommands.
#[derive(Subcommand)]
pub(crate) enum KeystoreCommand {
    /// Create a new password-protected keystore.
    Init,
    /// List all keys in the keystore (metadata only).
    List,
    /// Import a key file into the keystore.
    Import(ImportArgs),
    /// Export the secret key from the keystore to a key file.
    Export(ExportArgs),
    /// Export the public key from a keypair entry.
    ExportPublic(ExportPublicArgs),
    /// Rotate a key (replace with new key material).
    Rotate(RotateArgs),
    /// Delete a key from the keystore.
    Delete(DeleteArgs),
}

/// Arguments for the import command.
#[derive(Args)]
pub(crate) struct ImportArgs {
    /// Label for the key in the keystore.
    #[arg(short, long)]
    pub label: String,
    /// Path to the secret/symmetric key file to import.
    #[arg(short, long)]
    pub key_file: PathBuf,
    /// Path to the public key file (for asymmetric keypairs).
    #[arg(short, long)]
    pub public_key_file: Option<PathBuf>,
}

/// Arguments for the export command.
#[derive(Args)]
pub(crate) struct ExportArgs {
    /// Label of the key to export.
    #[arg(short, long)]
    pub label: String,
    /// Output path for the exported key file.
    #[arg(short, long)]
    pub output: PathBuf,
}

/// Arguments for the export-public command.
#[derive(Args)]
pub(crate) struct ExportPublicArgs {
    /// Label of the keypair to export the public key from.
    #[arg(short, long)]
    pub label: String,
    /// Output path for the public key file.
    #[arg(short, long)]
    pub output: PathBuf,
}

/// Arguments for the rotate command.
#[derive(Args)]
pub(crate) struct RotateArgs {
    /// Label of the key to rotate.
    #[arg(short, long)]
    pub label: String,
    /// Path to the new key file.
    #[arg(short, long)]
    pub new_key_file: PathBuf,
    /// Path to the new public key file (for keypair rotation).
    #[arg(short, long)]
    pub new_public_key_file: Option<PathBuf>,
}

/// Arguments for the delete command.
#[derive(Args)]
pub(crate) struct DeleteArgs {
    /// Label of the key to delete.
    #[arg(short, long)]
    pub label: String,
}

/// Execute the keystore command.
pub(crate) fn run(args: KeystoreArgs) -> Result<()> {
    match args.command {
        KeystoreCommand::Init => cmd_init(args.store_dir.as_deref()),
        KeystoreCommand::List => cmd_list(args.store_dir.as_deref()),
        KeystoreCommand::Import(import_args) => cmd_import(args.store_dir.as_deref(), import_args),
        KeystoreCommand::Export(export_args) => cmd_export(args.store_dir.as_deref(), export_args),
        KeystoreCommand::ExportPublic(export_args) => {
            cmd_export_public(args.store_dir.as_deref(), export_args)
        }
        KeystoreCommand::Rotate(rotate_args) => cmd_rotate(args.store_dir.as_deref(), rotate_args),
        KeystoreCommand::Delete(delete_args) => cmd_delete(args.store_dir.as_deref(), delete_args),
    }
}

fn read_password(prompt: &str) -> Result<Zeroizing<Vec<u8>>> {
    eprint!("{prompt}");
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    let trimmed = line.trim_end().as_bytes().to_vec();
    zeroize::Zeroize::zeroize(&mut line);
    Ok(Zeroizing::new(trimmed))
}

fn cmd_init(store_dir: Option<&std::path::Path>) -> Result<()> {
    let password = read_password("Enter new master password: ")?;
    if password.is_empty() {
        bail!("Password cannot be empty");
    }
    let confirm = read_password("Confirm master password: ")?;
    if password.as_slice() != confirm.as_slice() {
        bail!("Passwords do not match");
    }

    let store = KeyStore::create(&password, store_dir)?;
    println!("Keystore created at {}", store.path().display());
    Ok(())
}

fn cmd_list(store_dir: Option<&std::path::Path>) -> Result<()> {
    let password = read_password("Enter master password: ")?;
    let store = KeyStore::open(&password, store_dir)?;

    let entries = store.list();
    if entries.is_empty() {
        println!("Keystore is empty.");
        return Ok(());
    }

    println!("{:<20} {:<20} {:<10} {:<8} CREATED", "LABEL", "ALGORITHM", "TYPE", "ROTATED");
    println!("{}", "-".repeat(80));

    for (label, entry) in &entries {
        let type_str = match entry.key_type {
            StoredKeyType::Symmetric => "sym",
            StoredKeyType::Keypair => "keypair",
            StoredKeyType::Public => "pub",
        };
        println!(
            "{:<20} {:<20} {:<10} {:<8} {}",
            label,
            entry.algorithm,
            type_str,
            entry.rotation_count,
            &entry.created[..19], // trim timezone for display
        );
    }

    println!("\n{} key(s) total.", entries.len());
    Ok(())
}

fn cmd_import(store_dir: Option<&std::path::Path>, args: ImportArgs) -> Result<()> {
    let password = read_password("Enter master password: ")?;
    let mut store = KeyStore::open(&password, store_dir)?;

    let key_file = KeyFile::read_from(&args.key_file)?;
    let key_bytes = key_file.key_bytes()?;

    let (key_type, public_key_bytes) = if let Some(pk_path) = &args.public_key_file {
        let pk_file = KeyFile::read_from(pk_path)?;
        let pk_bytes = pk_file.key_bytes()?;
        (StoredKeyType::Keypair, Some(pk_bytes))
    } else {
        let kt = match key_file.key_type {
            KeyType::Symmetric => StoredKeyType::Symmetric,
            KeyType::Public => StoredKeyType::Public,
            KeyType::Secret => StoredKeyType::Keypair,
        };
        (kt, None)
    };

    let pk_ref: Option<&[u8]> = public_key_bytes.as_deref().map(AsRef::as_ref);
    let id = store.store(&args.label, &key_file.algorithm, key_type, &key_bytes, pk_ref)?;

    println!("Imported '{}' (id: {id})", args.label);
    Ok(())
}

fn cmd_export(store_dir: Option<&std::path::Path>, args: ExportArgs) -> Result<()> {
    let password = read_password("Enter master password: ")?;
    let store = KeyStore::open(&password, store_dir)?;

    let key_bytes = store.load(&args.label)?;
    let entry = store
        .list()
        .into_iter()
        .find(|(l, _)| *l == args.label)
        .map(|(_, e)| e.clone())
        .context("key entry not found after successful load")?;

    let key_type = match entry.key_type {
        StoredKeyType::Symmetric => KeyType::Symmetric,
        StoredKeyType::Keypair => KeyType::Secret,
        StoredKeyType::Public => KeyType::Public,
    };

    let kf = KeyFile::new(&entry.algorithm, key_type, &key_bytes, Some(args.label.clone()));
    kf.write_to(&args.output)?;

    println!("Exported '{}' to {}", args.label, args.output.display());
    Ok(())
}

fn cmd_export_public(store_dir: Option<&std::path::Path>, args: ExportPublicArgs) -> Result<()> {
    let password = read_password("Enter master password: ")?;
    let store = KeyStore::open(&password, store_dir)?;

    let pk_bytes = store.export_public(&args.label)?;
    let entry = store
        .list()
        .into_iter()
        .find(|(l, _)| *l == args.label)
        .map(|(_, e)| e.clone())
        .context("key entry not found after successful export")?;

    let kf = KeyFile::new(&entry.algorithm, KeyType::Public, &pk_bytes, Some(args.label.clone()));
    kf.write_to(&args.output)?;

    println!("Exported public key for '{}' to {}", args.label, args.output.display());
    Ok(())
}

fn cmd_rotate(store_dir: Option<&std::path::Path>, args: RotateArgs) -> Result<()> {
    let password = read_password("Enter master password: ")?;
    let mut store = KeyStore::open(&password, store_dir)?;

    let new_key_file = KeyFile::read_from(&args.new_key_file)?;
    let new_key_bytes = new_key_file.key_bytes()?;

    let new_pk_bytes = match &args.new_public_key_file {
        Some(pk_path) => {
            let pk_file = KeyFile::read_from(pk_path)?;
            Some(pk_file.key_bytes()?)
        }
        None => None,
    };

    let pk_ref: Option<&[u8]> = new_pk_bytes.as_deref().map(AsRef::as_ref);
    store.rotate(&args.label, &new_key_bytes, pk_ref)?;

    println!("Rotated key '{}'", args.label);
    Ok(())
}

fn cmd_delete(store_dir: Option<&std::path::Path>, args: DeleteArgs) -> Result<()> {
    let password = read_password("Enter master password: ")?;
    let mut store = KeyStore::open(&password, store_dir)?;

    store.delete(&args.label)?;
    println!("Deleted key '{}'", args.label);
    Ok(())
}
