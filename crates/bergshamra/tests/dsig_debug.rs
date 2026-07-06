use std::process::Command;

/// Runtime-owned directory for CLI integration fixtures.
///
/// The test writes multiple files with fixed names, so it first creates a
/// unique directory atomically and removes it when the test finishes.
struct TestDir {
    path: std::path::PathBuf,
}

impl TestDir {
    /// Create a unique temporary directory.
    fn new() -> Self {
        let base_nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock must be after unix epoch")
            .as_nanos();
        for attempt in 0..100_u32 {
            let path = std::env::temp_dir().join(format!(
                "bergshamra-cli-dsig-debug-{pid}-{base_nonce}-{attempt}",
                pid = std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    panic!(
                        "temporary CLI fixture directory {} must be creatable: {err}",
                        path.display()
                    );
                }
            }
        }

        panic!("temporary CLI fixture directory path must be unique after retries");
    }

    /// Return a child path inside this temporary directory.
    fn join(&self, name: &str) -> std::path::PathBuf {
        self.path.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn verify_debug_redacts_detached_reference_bytes() {
    // The signature is intentionally invalid: verification only needs to reach
    // reference digest processing, where debug output previously printed the
    // detached file bytes before reporting the digest mismatch.
    let dir = TestDir::new();
    let detached_secret = "detached debug secret";
    std::fs::write(dir.join("payload.txt"), detached_secret)
        .expect("detached payload fixture must be writable");
    std::fs::write(dir.join("hmac.key"), b"test hmac key")
        .expect("HMAC key fixture must be writable");
    std::fs::write(
        dir.join("signature.xml"),
        r#"<Root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>
      <ds:Reference URI="payload.txt">
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>AAAA</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>AAAA</ds:SignatureValue>
  </ds:Signature>
</Root>"#,
    )
    .expect("signature fixture must be writable");

    let output = Command::new(env!("CARGO_BIN_EXE_bergshamra"))
        .arg("verify")
        .arg("--debug")
        .arg("--hmac-key")
        .arg(dir.join("hmac.key"))
        .arg(dir.join("signature.xml"))
        .output()
        .expect("bergshamra verify command must run");

    assert!(
        !output.status.success(),
        "invalid signature fixture must fail verification"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("[external reference bytes redacted:"),
        "debug stderr must contain the detached-reference redaction marker: {stderr}"
    );
    assert!(
        !stderr.contains(detached_secret),
        "debug stderr must not contain detached file contents: {stderr}"
    );
}
