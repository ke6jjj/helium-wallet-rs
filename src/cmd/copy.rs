use crate::{
    cmd::{get_file_extension, get_password_ex, load_wallet, open_output_file, verify, Opts},
    format::{self, Format},
    pwhash::PwHash,
    result::Result,
    wallet::Wallet,
};
use std::path::PathBuf;
use structopt::StructOpt;

#[derive(Debug, StructOpt)]
/// Copy a wallet to the latest supported version of the given
/// format. Different passwords will be used for the source and
/// destination.
pub enum Cmd {
    Basic(Basic),
    Sharded(Sharded),
    Idiot(Idiot)
}

#[derive(Debug, StructOpt)]
/// Copy a wallet, changing password and/or format
pub struct Basic {
    #[structopt(long)]
    /// Overwrite an existing file
    force: bool,

    #[structopt(short, long)]
    /// Output file to store the key in
    output: PathBuf,
}

#[derive(Debug, StructOpt)]
/// Upgrade to the latest sharded wallet format
pub struct Sharded {
    #[structopt(long)]
    /// Overwrite an existing file
    force: bool,

    #[structopt(short, long)]
    /// Output file to store the key in
    output: PathBuf,

    #[structopt(short = "n", long = "shards", default_value = "5")]
    /// Number of shards to break the key into
    key_share_count: u8,

    #[structopt(short = "k", long = "required-shards", default_value = "3")]
    /// Number of shards required to recover the key
    recovery_threshold: u8,
}

#[derive(Debug, StructOpt)]
/// Upgrade to an Idiot wallet.
pub struct Idiot {
    #[structopt(long)]
    /// Overwrite an existing file
    force: bool,

    #[structopt(short, long)]
    /// Output file to store the key in
    output: PathBuf,
}

impl Cmd {
    pub fn run(&self, opts: Opts) -> Result {
        match self {
            Cmd::Basic(cmd) => cmd.run(opts),
            Cmd::Sharded(cmd) => cmd.run(opts),
            Cmd::Idiot(cmd) => cmd.run(opts),
        }
    }
}

impl Basic {
    pub fn run(&self, opts: Opts) -> Result {
        let password = get_password_ex(false, 0, "Source wallet password")?;
        let wallet = load_wallet(opts.files)?;
        let keypair = wallet.decrypt(password.as_bytes())?;

        let format = format::Basic {
            pwhash: PwHash::argon2id13_default(),
        };
        let output_password = get_password_ex(true, 1, "Destination wallet password")?;
        let new_wallet = Wallet::encrypt(&keypair, output_password.as_bytes(), Format::Basic(format))?;
        let mut writer = open_output_file(&self.output, !self.force)?;
        new_wallet.write(&mut writer)?;
        verify::print_result(&new_wallet, true, opts.format)
    }
}

impl Sharded {
    pub fn run(&self, opts: Opts) -> Result {
        let password = get_password_ex(false, 0, "Source wallet password")?;
        let wallet = load_wallet(opts.files)?;
        let keypair = wallet.decrypt(password.as_bytes())?;

        let format = format::Sharded {
            key_share_count: self.key_share_count,
            recovery_threshold: self.recovery_threshold,
            pwhash: PwHash::argon2id13_default(),
            key_shares: vec![],
        };
        let output_password = get_password_ex(true, 1, "Destination wallet password")?;
        let new_wallet = Wallet::encrypt(&keypair, output_password.as_bytes(), Format::Sharded(format))?;

        let extension = get_file_extension(&self.output);
        for (i, shard) in new_wallet.shards()?.iter().enumerate() {
            let mut filename = self.output.clone();
            let share_extension = format!("{}.{}", extension, (i + 1).to_string());
            filename.set_extension(share_extension);
            let mut writer = open_output_file(&filename, !self.force)?;
            shard.write(&mut writer)?;
        }
        verify::print_result(&new_wallet, true, opts.format)
    }
}

impl Idiot {
    pub fn run(&self, opts: Opts) -> Result {
        let password = get_password_ex(false, 0, "Source wallet password")?;
        let wallet = load_wallet(opts.files)?;
        let keypair = wallet.decrypt(password.as_bytes())?;
        let format = format::Basic {
            pwhash: PwHash::hex_default(),
        };
        let output_password = get_password_ex(true, 1, "Destination wallet password")?;
        let new_wallet = Wallet::encrypt(&keypair, output_password.as_bytes(), Format::Basic(format))?;
        let mut writer = open_output_file(&self.output, !self.force)?;
        new_wallet.write(&mut writer)?;
        verify::print_result(&new_wallet, true, opts.format)
    }
}
