/// Run after `op run` resolves references and before Compose starts.
/// Decoding changes the value that `op run` knows how to mask, so also
/// conceal decoded private-key lines on both child output streams.
/// Values are never evaluated; only literal backslash-n is decoded.
pub(crate) const PRIVATE_KEY_SCRIPT: &str = r#"_komodo_private_keys() {
  local __komodo_name __komodo_value __komodo_decoded __komodo_part __komodo_status;
  local -a __komodo_masks=();
  while IFS= read -r __komodo_name; do
    if [[ "$__komodo_name" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ && "$__komodo_name" == *PRIVATE_KEY* ]]; then
      __komodo_value=${!__komodo_name};
      __komodo_decoded=${__komodo_value//\\n/$'\n'};
      if [[ "$__komodo_decoded" != "$__komodo_value" ]]; then
        while IFS= read -r __komodo_part || [[ -n "$__komodo_part" ]]; do
          [[ -z "$__komodo_part" ]] || __komodo_masks+=("$__komodo_part");
        done <<< "$__komodo_decoded";
        export "$__komodo_name=$__komodo_decoded";
      fi;
    fi;
  done < <(compgen -e);
  _komodo_mask_keys() {
    local __komodo_line __komodo_mask;
    while IFS= read -r __komodo_line || [[ -n "$__komodo_line" ]]; do
      for __komodo_mask in "${__komodo_masks[@]}"; do
        __komodo_line=${__komodo_line//"$__komodo_mask"/'<concealed private key>'};
      done;
      printf '%s\n' "$__komodo_line";
    done;
  };
  "$@" > >(_komodo_mask_keys) 2> >(_komodo_mask_keys >&2);
  __komodo_status=$?;
  wait;
  return "$__komodo_status";
};
_komodo_private_keys "$@";"#;

#[cfg(test)]
mod tests {
  use super::PRIVATE_KEY_SCRIPT;
  use std::process::Command;

  #[test]
  fn decodes_private_keys_only_and_preserves_arguments() {
    let result = Command::new("bash")
      .args(["-c", &PRIVATE_KEY_SCRIPT.replace('\n', " "), "--", "bash", "-c"])
      .arg(r#"[[ "$FORWARDER_PRIVATE_KEY" == $'header\nbody\nfooter\n' && "$PREFIX_PRIVATE_KEY_SUFFIX" == $'one\ntwo' && "$PUBLIC_KEY" == 'one\ntwo' && "$OTHER_SECRET" == 'one\ntwo' && "$1" == 'argument with spaces; $(false)' ]]"#)
      .args(["--", "argument with spaces; $(false)"])
      .env("FORWARDER_PRIVATE_KEY", "header\\nbody\\nfooter\\n")
      .env("PREFIX_PRIVATE_KEY_SUFFIX", "one\\ntwo")
      .env("PUBLIC_KEY", "one\\ntwo")
      .env("OTHER_SECRET", "one\\ntwo")
      .status()
      .expect("run Bash normalizer");
    assert!(result.success());
  }

  #[test]
  fn preserves_real_newlines_empty_values_and_other_escapes() {
    let result = Command::new("bash")
      .args(["-c", &PRIVATE_KEY_SCRIPT.replace('\n', " "), "--", "bash", "-c"])
      .arg(r#"[[ "$REAL_PRIVATE_KEY" == $'header\nbody\nfooter\n' && -z "$EMPTY_PRIVATE_KEY" && "$OTHER_PRIVATE_KEY" == 'quotes " $HOME $(false) \t \r' && "$name" == original && "$value" == original ]]"#)
      .env("REAL_PRIVATE_KEY", "header\nbody\nfooter\n")
      .env("EMPTY_PRIVATE_KEY", "")
      .env("OTHER_PRIVATE_KEY", r#"quotes " $HOME $(false) \t \r"#)
      .env("name", "original")
      .env("value", "original")
      .status()
      .expect("run Bash normalizer");
    assert!(result.success());
  }

  #[test]
  fn masks_decoded_keys_on_stdout_and_stderr() {
    let result = Command::new("bash")
      .args(["-c", &PRIVATE_KEY_SCRIPT.replace('\n', " "), "--", "bash", "-c"])
      .arg(r#"printf '%s\n' "$TEST_PRIVATE_KEY"; printf '%s\n' "$TEST_PRIVATE_KEY" >&2"#)
      .env("TEST_PRIVATE_KEY", "first-key-line\\nsecond-key-line")
      .output()
      .expect("run Bash normalizer");
    assert!(result.status.success());
    for output in [result.stdout, result.stderr] {
      assert_eq!(
        output,
        b"<concealed private key>\n<concealed private key>\n"
      );
    }
  }

  #[test]
  fn survives_the_compose_wrapper_parser() {
    use std::borrow::Cow;

    let script = shell_escape::unix::escape(Cow::Owned(
      PRIVATE_KEY_SCRIPT.replace('\n', " "),
    ));
    let wrapper = format!(
      "bash -c {script} -- bash -c '[[ \"$TEST_PRIVATE_KEY\" == \"$EXPECTED\" ]]'"
    );
    let parsed =
      komodo_client::parsers::parse_multiline_command(wrapper);
    let result = Command::new("sh")
      .args(["-c", &parsed])
      .env("TEST_PRIVATE_KEY", "first\\nsecond")
      .env("EXPECTED", "first\nsecond")
      .status()
      .expect("run parsed wrapper");
    assert!(result.success());
  }

  #[test]
  fn preserves_child_exit_status() {
    let result = Command::new("bash")
      .args([
        "-c",
        &PRIVATE_KEY_SCRIPT.replace('\n', " "),
        "--",
        "bash",
        "-c",
        "exit 37",
      ])
      .status()
      .expect("run Bash normalizer");
    assert_eq!(result.code(), Some(37));
  }
}
