use super::*;

#[test]
fn test_codeview_rsds_roundtrip() {
    let original = CodeViewRsds {
        guid: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16],
        age: 1,
        pdb_path: b"C:\\path\\to\\file.pdb".to_vec(),
    };

    let bytes = original.to_bytes();
    let parsed = CodeViewRsds::parse(&bytes).unwrap();
    assert_eq!(parsed, original);
    assert_eq!(parsed.pdb_path_str(), Some("C:\\path\\to\\file.pdb"));
}

#[test]
fn an_ansi_path_parses_and_keeps_its_bytes() {
    // 0xE9 is "é" in Windows-1252, and it is not valid UTF-8 alone.
    let original = CodeViewRsds {
        guid: [9; 16],
        age: 2,
        pdb_path: b"\xe9t\xe9.pdb".to_vec(),
    };
    let parsed = CodeViewRsds::parse(&original.to_bytes()).unwrap();
    assert_eq!(parsed.pdb_path, b"\xe9t\xe9.pdb");
    assert_eq!(parsed.pdb_path_str(), None);
    assert_eq!(parsed.pdb_path_lossy(), "\u{fffd}t\u{fffd}.pdb");
    assert_eq!(parsed.to_bytes(), original.to_bytes());
}

#[test]
fn a_path_without_a_terminator_is_an_error() {
    let mut bytes = CodeViewRsds {
        guid: [0; 16],
        age: 0,
        pdb_path: b"a.pdb".to_vec(),
    }
    .to_bytes();
    bytes.pop();
    assert!(CodeViewRsds::parse(&bytes).is_err());
}
