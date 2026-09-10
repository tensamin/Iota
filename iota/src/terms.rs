use crate::startup_error::StartupError;
use iota_terms::{LegalDocument, TermsType, consent, get_current_docs, get_terms};
use std::io::{self, IsTerminal, Write};

pub enum TermsCommand {
    Status { system: bool },
    Show { document: TermsType },
    Accept { system: bool },
}

fn state_dir(system: bool) -> Result<std::path::PathBuf, StartupError> {
    let scope = if system {
        iota_paths::Scope::System
    } else {
        iota_paths::Scope::User
    };
    iota_paths::IotaPaths::resolve(scope)
        .map(|paths| paths.state_dir)
        .map_err(|error| StartupError::Other(format!("Cannot resolve consent storage: {error}")))
}

pub async fn run(command: TermsCommand) -> Result<(), StartupError> {
    match command {
        TermsCommand::Status { system } => {
            let record = consent::load(&state_dir(system)?);
            println!(
                "EULA: {}",
                if record.eula.is_some() {
                    "accepted"
                } else {
                    "not accepted"
                }
            );
            println!(
                "Terms of Service: {}",
                if record.tos.is_some() {
                    "accepted"
                } else {
                    "not accepted"
                }
            );
            println!(
                "Privacy Policy: {}",
                if record.privacy.is_some() {
                    "accepted"
                } else {
                    "not accepted"
                }
            );
            Ok(())
        }
        TermsCommand::Show { document } => {
            let text = get_terms(document).await.ok_or_else(|| {
                StartupError::Consent("Could not fetch the requested terms document.".into())
            })?;
            print!("{text}");
            Ok(())
        }
        TermsCommand::Accept { system } => accept(system).await,
    }
}

async fn accept(system: bool) -> Result<(), StartupError> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(StartupError::Consent("`iota terms accept` requires an interactive terminal so the documents can be reviewed.".into()));
    }
    let documents = get_current_docs().await.ok_or_else(|| {
        StartupError::Consent(
            "Could not fetch the current agreements from the legal endpoint.".into(),
        )
    })?;
    let mut record = consent::load(&state_dir(system)?);
    for document in [&documents.0, &documents.1, &documents.2] {
        println!(
            "\n===== {} =====\nVersion: {}\nDocument hash: {}\n",
            document.kind().to_string(),
            document.version(),
            document.hash()
        );
        print!("{}\n", document.content());
        if !confirm(document)? {
            return Err(StartupError::Consent(
                "No terms were accepted. Iota remains inactive.".into(),
            ));
        }
        record.accept(&document.metadata());
    }
    consent::save(&state_dir(system)?, &record)
        .map_err(|error| StartupError::Consent(format!("Could not save consent: {error}")))?;
    println!("Terms accepted. Start Iota again to enable services.");
    Ok(())
}

fn confirm(document: &LegalDocument) -> Result<bool, StartupError> {
    let prefix = document.hash().get(..10).unwrap_or(document.hash());
    let expected = format!(
        "ACCEPT {} {} {}",
        document.kind().to_str().to_ascii_uppercase(),
        document.version(),
        prefix
    );
    print!("To accept this exact document, type:\n{expected}\n> ");
    io::stdout()
        .flush()
        .map_err(|error| StartupError::Consent(error.to_string()))?;
    let mut response = String::new();
    io::stdin()
        .read_line(&mut response)
        .map_err(|error| StartupError::Consent(error.to_string()))?;
    Ok(response.trim() == expected)
}
