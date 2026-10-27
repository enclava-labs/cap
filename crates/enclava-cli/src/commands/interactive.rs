//! Prompt gating shared by every dialoguer site.
//!
//! A prompt may render only in a real terminal session (stdin AND stderr —
//! dialoguer draws on stderr) with prompting enabled: `--no-input` (or
//! `ENCLAVA_NO_INPUT`) forces the non-interactive behavior even under a pty,
//! where a session with no stdin feeder would otherwise block silently at the
//! prompt. Every prompt has a flag escape, and a refusal names it.

use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};

static NO_INPUT: AtomicBool = AtomicBool::new(false);

pub(crate) fn set_no_input(no_input: bool) {
    NO_INPUT.store(no_input, Ordering::Relaxed);
}

pub(crate) fn no_input() -> bool {
    NO_INPUT.load(Ordering::Relaxed)
}

/// stdin half of the interactive-session check (`--no-input` forces false).
pub(crate) fn stdin_interactive() -> bool {
    session_interactive_for(std::io::stdin().is_terminal(), no_input())
}

/// stderr half of the interactive-session check (`--no-input` forces false).
pub(crate) fn stderr_interactive() -> bool {
    session_interactive_for(std::io::stderr().is_terminal(), no_input())
}

pub(crate) fn session_interactive_for(is_terminal: bool, no_input: bool) -> bool {
    is_terminal && !no_input
}

/// True when a prompt may be rendered.
pub(crate) fn prompts_available() -> bool {
    stdin_interactive() && stderr_interactive()
}

/// Refuse a prompt, naming the flag or workaround that replaces it.
pub(crate) fn require_prompt(escape: &str) -> Result<(), Box<dyn std::error::Error>> {
    require_prompt_for(prompts_available(), escape)
}

pub(crate) fn require_prompt_for(
    prompts_available: bool,
    escape: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if prompts_available {
        Ok(())
    } else {
        Err(
            format!("this step would prompt for input in a non-interactive session; {escape}")
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_input_disables_prompting_even_on_terminals() {
        for (is_terminal, no_input, expected) in [
            (true, false, true),
            (true, true, false),
            (false, false, false),
            (false, true, false),
        ] {
            assert_eq!(
                session_interactive_for(is_terminal, no_input),
                expected,
                "is_terminal={is_terminal} no_input={no_input}"
            );
        }
    }

    #[test]
    fn prompt_refusal_names_the_flag_escape() {
        let err = require_prompt_for(false, "pass --force to destroy without confirmation")
            .expect_err("non-interactive sessions must refuse prompts");
        assert!(err.to_string().contains("pass --force"), "{err}");
        require_prompt_for(true, "pass --force").expect("interactive sessions may prompt");
    }

    /// Tripwire (house source-contract pattern): every prompt site keeps its
    /// flag escape in the refusal message. Deleting a gate deletes its needle.
    #[test]
    fn every_prompt_site_names_its_escape() {
        for (source, needles) in [
            (include_str!("mod.rs"), &["ENCLAVA_NO_INPUT"][..]),
            (
                include_str!("app.rs"),
                &[
                    "pass --force to destroy without confirmation",
                    "pass --to <deployment-id> to roll back without confirmation",
                    "--storage-password-file <PATH> to provide the storage password non-interactively",
                ][..],
            ),
            (
                include_str!("auth.rs"),
                &[
                    "pass --replace-session",
                    "pass --email or --nostr to choose the login method",
                    "pass --email or --nostr to choose the signup method",
                    "--email-address <EMAIL> and --password-file <PATH>",
                    "--npub <NPUB> and --nsec-file <PATH>",
                ][..],
            ),
            (
                include_str!("prepare.rs"),
                &["pass --yes to update the existing files without confirmation"][..],
            ),
            (
                include_str!("key.rs"),
                &["pass --yes to rotate the owner key without confirmation"][..],
            ),
            (
                include_str!("org.rs"),
                &["pass --yes to confirm trust on first use without prompting"][..],
            ),
        ] {
            for needle in needles {
                assert!(source.contains(needle), "missing prompt escape: {needle}");
            }
        }
    }
}
