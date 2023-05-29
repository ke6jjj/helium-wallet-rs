use crate::{cmd::*, result::Result};

#[derive(Clone, Debug, clap::Args)]
/// Get the claimable rewards for a Hotspot. The rewards are given for each
/// of the Helium-related networks the Hotspot belongs to.
pub struct Cmd {
    ecc_key: helium_crypto::PublicKey,
}

impl Cmd {
    pub fn run(&self, opts: Opts) -> Result {
        let client = new_client(&opts.url)?;

        let account = client.get_current_rewards_key(
            &self.ecc_key
        )?;
        let json = json!({
            "asset": account,
        });
        print_json(&json)
    }
}
