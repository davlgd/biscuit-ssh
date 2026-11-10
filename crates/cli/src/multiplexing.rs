//! Keeping `ssh` from joining a multiplexed connection.
//!
//! With `ControlMaster` set in its configuration, `ssh` joins an open
//! connection to the same destination without logging in: the bastion or
//! the server would never see the token, certificate, or command of this
//! invocation. So `biscuit-ssh ssh` always logs in afresh, with
//! [`FRESH_LOGIN`]. Explicit multiplexing options in the arguments of `ssh`
//! still apply, except with a forced command, which [`refuse`]s them.

use anyhow::bail;

/// Options disabling multiplexing, placed before any other `ssh` argument:
/// the first value of an option wins, over the configuration files too.
pub const FRESH_LOGIN: [&str; 4] = ["-o", "ControlMaster=no", "-o", "ControlPath=none"];

/// Fails if `ssh_args` hold a multiplexing option, which could join a
/// connection opened without the forced command.
pub fn refuse(ssh_args: &[String]) -> anyhow::Result<()> {
    if let Some(option) = option(ssh_args) {
        bail!("--command needs a connection of its own: remove {option}");
    }
    Ok(())
}

/// `ssh` options taking a value, as in its `getopt` string.
const SSH_OPTIONS_WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";

/// The first multiplexing option among the `ssh` options of `ssh_args`,
/// which stop at the remote command: `-M`, `-S`, `-O`, or `-o` with a
/// `Control…` setting.
pub fn option(ssh_args: &[String]) -> Option<String> {
    let mut args = ssh_args.iter();
    while let Some(arg) = args.next() {
        if arg == "--" || !arg.starts_with('-') || arg.len() < 2 {
            return None;
        }
        for (index, letter) in arg.char_indices().skip(1) {
            if letter == 'M' {
                return Some("-M".to_owned());
            }
            if SSH_OPTIONS_WITH_VALUE.contains(letter) {
                let inline = &arg[index + letter.len_utf8()..];
                let value = if inline.is_empty() {
                    args.next().map_or("", String::as_str)
                } else {
                    inline
                };
                let control = value.trim_start().to_ascii_lowercase().starts_with("control");
                if matches!(letter, 'S' | 'O') || (letter == 'o' && control) {
                    return Some(format!("-{letter} {value}"));
                }
                break;
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_multiplexing_options_before_the_remote_command() {
        let found = |args: &[&str]| option(&args.iter().map(|a| a.to_string()).collect::<Vec<_>>());
        for (args, option) in [
            (&["-S", "/tmp/mux"][..], "-S /tmp/mux"),
            (&["-v", "-S/tmp/mux"], "-S /tmp/mux"),
            (&["-qM"], "-M"),
            (&["-p", "22", "-o", "ControlPath=/tmp/x"], "-o ControlPath=/tmp/x"),
            (&["-oControlMaster=auto"], "-o ControlMaster=auto"),
            (&["-O", "exit"], "-O exit"),
        ] {
            assert_eq!(found(args).as_deref(), Some(option), "{args:?}");
        }
        for args in [
            &["sort", "-S", "10M"][..],
            &["-p", "-S"],
            &["-o", "User=x", "uptime", "-M"],
            &["--", "-S", "x"],
            &["-i", "-M"],
        ] {
            assert_eq!(found(args), None, "{args:?}");
        }
    }
}
