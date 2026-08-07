//! Logical document paths.
//!
//! Names are relative, forward-slashed, and held in the encrypted index, then
//! turned back into filesystem paths by `open` and `export`, so a name like
//! `../../etc/hosts` must never escape the vault folder. Validation runs on the
//! way in and again on the way out, so a vault written by a buggy or future
//! version still cannot write outside its own folder.

use std::path::{Component, Path, PathBuf};

use crate::{Error, Result};

/// Longest logical path accepted, in bytes.
const MAX_PATH_LEN: usize = 1024;

/// Longest single component, kept clear of the 255-byte filesystem limit.
const MAX_COMPONENT_LEN: usize = 200;

/// Device names Windows resolves specially in any directory.
const RESERVED_STEMS: &[&str] = &[
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// A validated, relative, forward-slashed document name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DocPath(String);

impl DocPath {
    /// Validate and normalize a logical path.
    pub fn new(raw: &str) -> Result<Self> {
        let normalized = raw.replace('\\', "/");
        let trimmed = normalized.trim_matches('/');

        if trimmed.is_empty() {
            return Err(reject(raw, "the path is empty"));
        }
        if trimmed.len() > MAX_PATH_LEN {
            return Err(reject(raw, "the path is too long"));
        }

        let mut components = Vec::new();
        for component in trimmed.split('/') {
            // Collapse redundant separators without dropping anything meaningful.
            if component.is_empty() || component == "." {
                continue;
            }
            validate_component(raw, component)?;
            components.push(component);
        }

        if components.is_empty() {
            return Err(reject(raw, "the path names no document"));
        }

        // `.encino/anything` would resolve on top of the index itself.
        if components[0].eq_ignore_ascii_case(crate::VAULT_DIR) {
            return Err(reject(raw, "`.encino` is reserved for the vault's own storage"));
        }

        Ok(DocPath(components.join("/")))
    }

    /// Derive a logical path from a filesystem path relative to some base.
    pub fn from_relative(relative: &Path) -> Result<Self> {
        let mut parts = Vec::new();
        for component in relative.components() {
            match component {
                Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
                Component::CurDir => {}
                other => {
                    return Err(reject(
                        &relative.to_string_lossy(),
                        &format!("{other:?} is not allowed in a document name"),
                    ));
                }
            }
        }
        DocPath::new(&parts.join("/"))
    }

    /// The logical path as stored in the index.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The final component, for display.
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or(&self.0)
    }

    /// Resolve to a real path underneath `base`. Re-validates rather than
    /// trusting the stored name, then confirms the result is still inside `base`.
    pub fn resolve_under(&self, base: &Path) -> Result<PathBuf> {
        let revalidated = DocPath::new(&self.0)?;

        let mut resolved = base.to_path_buf();
        for component in revalidated.0.split('/') {
            resolved.push(component);
        }

        if !resolved.starts_with(base) {
            return Err(reject(&self.0, "the path escapes the vault folder"));
        }
        Ok(resolved)
    }
}

impl std::fmt::Display for DocPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl serde::Serialize for DocPath {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> serde::Deserialize<'de> for DocPath {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        DocPath::new(&raw).map_err(serde::de::Error::custom)
    }
}

fn reject(raw: &str, reason: &str) -> Error {
    Error::InvalidDocumentPath { path: raw.to_string(), reason: reason.to_string() }
}

fn validate_component(raw: &str, component: &str) -> Result<()> {
    if component == ".." {
        return Err(reject(raw, "`..` would escape the vault folder"));
    }
    if component.len() > MAX_COMPONENT_LEN {
        return Err(reject(raw, "a path component is too long"));
    }

    // A colon is either a drive letter or an NTFS alternate data stream.
    if let Some(bad) = component.chars().find(|c| matches!(c, '<' | '>' | ':' | '"' | '|' | '?' | '*')) {
        return Err(reject(raw, &format!("`{bad}` is not allowed in a filename")));
    }
    if component.chars().any(|c| c.is_control()) {
        return Err(reject(raw, "control characters are not allowed in a filename"));
    }

    // Windows strips these, so `report.` and `report` would collide on disk.
    if component.ends_with('.') || component.ends_with(' ') || component.starts_with(' ') {
        return Err(reject(raw, "a filename may not begin or end with a space or a dot"));
    }

    let stem = component.split('.').next().unwrap_or(component).to_lowercase();
    if RESERVED_STEMS.contains(&stem.as_str()) {
        return Err(reject(raw, &format!("`{stem}` is a reserved device name on Windows")));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_paths_are_accepted_and_normalized() {
        assert_eq!(DocPath::new("2024-w2.pdf").unwrap().as_str(), "2024-w2.pdf");
        assert_eq!(DocPath::new("taxes/2024/w2.pdf").unwrap().as_str(), "taxes/2024/w2.pdf");
        assert_eq!(DocPath::new("taxes\\2024\\w2.pdf").unwrap().as_str(), "taxes/2024/w2.pdf");
        assert_eq!(DocPath::new("/taxes//2024/./w2.pdf/").unwrap().as_str(), "taxes/2024/w2.pdf");
    }

    #[test]
    fn unicode_names_are_preserved() {
        for name in ["relevé-bancaire.pdf", "確定申告.pdf", "naïve café.txt", "emoji 📄.pdf"] {
            assert_eq!(DocPath::new(name).unwrap().as_str(), name);
        }
    }

    #[test]
    fn traversal_is_refused_in_every_position() {
        for attempt in [
            "../secrets.txt",
            "taxes/../../secrets.txt",
            "taxes/../2024/../../../etc/passwd",
            "..",
            "../",
            "a/../../b",
        ] {
            assert!(
                matches!(DocPath::new(attempt), Err(Error::InvalidDocumentPath { .. })),
                "{attempt:?} should have been refused"
            );
        }
    }

    #[test]
    fn absolute_and_device_paths_are_refused() {
        for attempt in ["C:/Windows/System32/config", "C:\\Windows\\notes.txt", "file.txt:hidden"] {
            assert!(
                matches!(DocPath::new(attempt), Err(Error::InvalidDocumentPath { .. })),
                "{attempt:?} should have been refused"
            );
        }
    }

    #[test]
    fn windows_reserved_names_are_refused() {
        for attempt in ["con", "CON", "nul.txt", "com1", "LPT9.pdf", "taxes/aux.pdf"] {
            assert!(
                matches!(DocPath::new(attempt), Err(Error::InvalidDocumentPath { .. })),
                "{attempt:?} should have been refused"
            );
        }
        assert!(DocPath::new("console.txt").is_ok());
        assert!(DocPath::new("nullify.pdf").is_ok());
    }

    #[test]
    fn trailing_dots_and_spaces_are_refused() {
        for attempt in ["report.", "report ", " report", "taxes/2024./w2.pdf"] {
            assert!(
                matches!(DocPath::new(attempt), Err(Error::InvalidDocumentPath { .. })),
                "{attempt:?} should have been refused"
            );
        }
    }

    #[test]
    fn the_vaults_own_directory_cannot_be_named_as_a_document() {
        for attempt in [".encino/index.enc", ".encino", ".ENCINO/vault.json", ".encino/blobs/00/aa"] {
            assert!(
                matches!(DocPath::new(attempt), Err(Error::InvalidDocumentPath { .. })),
                "{attempt:?} should have been refused"
            );
        }
        assert!(DocPath::new("notes/.encino-notes.txt").is_ok());
    }

    #[test]
    fn empty_and_oversized_paths_are_refused() {
        assert!(DocPath::new("").is_err());
        assert!(DocPath::new("/").is_err());
        assert!(DocPath::new("///").is_err());
        assert!(DocPath::new(".").is_err());
        assert!(DocPath::new(&"a".repeat(MAX_COMPONENT_LEN + 1)).is_err());
        assert!(DocPath::new(&vec!["dir"; 400].join("/")).is_err());
    }

    #[test]
    fn control_characters_are_refused() {
        assert!(DocPath::new("bad\nname.txt").is_err());
        assert!(DocPath::new("bad\0name.txt").is_err());
        assert!(DocPath::new("bad\tname.txt").is_err());
    }

    #[test]
    fn resolution_stays_inside_the_base_directory() {
        let base = Path::new("E:\\vault");
        let resolved = DocPath::new("taxes/2024/w2.pdf").unwrap().resolve_under(base).unwrap();

        assert!(resolved.starts_with(base));
        assert!(resolved.ends_with("w2.pdf"));
    }

    #[test]
    fn a_hostile_path_smuggled_past_the_constructor_is_caught_at_resolution() {
        // Simulates an index written by a buggy or malicious build.
        let smuggled = DocPath("../../Windows/System32/drivers/etc/hosts".to_string());
        assert!(smuggled.resolve_under(Path::new("E:\\vault")).is_err());

        let absolute = DocPath("C:/Windows/System32/config".to_string());
        assert!(absolute.resolve_under(Path::new("E:\\vault")).is_err());
    }

    #[test]
    fn deserialization_refuses_hostile_paths() {
        let hostile = serde_json::json!("../../escape.txt").to_string();
        assert!(serde_json::from_str::<DocPath>(&hostile).is_err());

        let fine = serde_json::json!("taxes/w2.pdf").to_string();
        assert_eq!(serde_json::from_str::<DocPath>(&fine).unwrap().as_str(), "taxes/w2.pdf");
    }

    #[test]
    fn file_name_returns_the_last_component() {
        assert_eq!(DocPath::new("taxes/2024/w2.pdf").unwrap().file_name(), "w2.pdf");
        assert_eq!(DocPath::new("w2.pdf").unwrap().file_name(), "w2.pdf");
    }

    #[test]
    fn from_relative_matches_the_string_constructor() {
        let from_path = DocPath::from_relative(Path::new("taxes/2024/w2.pdf")).unwrap();
        assert_eq!(from_path, DocPath::new("taxes/2024/w2.pdf").unwrap());

        assert!(DocPath::from_relative(Path::new("../escape.txt")).is_err());
        assert!(DocPath::from_relative(Path::new("C:\\absolute.txt")).is_err());
    }
}
