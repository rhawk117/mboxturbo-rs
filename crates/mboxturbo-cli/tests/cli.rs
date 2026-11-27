//! The built `mboxturbo` binary prints its version and help and rejects bad arguments with
//! exit code 64.

#[cfg(test)]
mod cli {
    use std::process::{Command, Output};

    fn run(args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_mboxturbo"))
            .args(args)
            .output()
            .expect("the built mboxturbo binary runs")
    }

    #[test]
    fn version_prints_the_workspace_version_and_exits_zero() {
        let output = run(&["--version"]);
        assert_eq!(output.status.code(), Some(0_i32), "--version exits 0");
        let expected = format!("mboxturbo {}\n", env!("CARGO_PKG_VERSION"));
        assert_eq!(
            String::from_utf8_lossy(&output.stdout),
            expected,
            "--version prints the name and version"
        );
    }

    #[test]
    fn help_exits_zero() {
        let output = run(&["--help"]);
        assert_eq!(output.status.code(), Some(0_i32), "--help exits 0");
        assert!(!output.stdout.is_empty(), "--help prints usage on stdout");
    }

    #[test]
    fn an_unknown_flag_exits_64_with_clap_message_on_stderr() {
        let output = run(&["--bogus"]);
        assert_eq!(
            output.status.code(),
            Some(64_i32),
            "a usage error exits 64, not clap's 2"
        );
        assert!(!output.stderr.is_empty(), "clap's message goes to stderr");
        assert!(output.stdout.is_empty(), "nothing is printed on stdout");
    }
}
