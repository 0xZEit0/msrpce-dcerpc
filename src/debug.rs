use std::fmt::Write;

pub fn hex_preview(bytes: &[u8], max_len: usize) -> String {
    let shown = bytes.len().min(max_len);
    let mut out = String::new();
    for (index, byte) in bytes[..shown].iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        write!(&mut out, "{byte:02X}").expect("writing to a String cannot fail");
    }

    if bytes.len() > shown {
        if !out.is_empty() {
            out.push(' ');
        }
        write!(&mut out, "... (+{} bytes)", bytes.len() - shown)
            .expect("writing to a String cannot fail");
    }

    out
}

pub fn redacted_bytes(label: &str, bytes: &[u8]) -> String {
    format!("{label}=<redacted: {} bytes>", bytes.len())
}
