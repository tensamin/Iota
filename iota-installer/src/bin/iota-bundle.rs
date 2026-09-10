use anyhow::{Context, Result, bail};
use std::path::Path;

fn main() -> Result<()> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let bundle = arguments.next().context("usage: iota-bundle BUNDLE.zip")?;
    if arguments.next().is_some() {
        bail!("usage: iota-bundle BUNDLE.zip");
    }
    iota_installer::validate_linux_bundle(Path::new(&bundle))
}
