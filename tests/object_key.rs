//! `ObjectKey` 校验边界。

use s3x::{ObjectKey, S3Error, MAX_OBJECT_KEY_BYTES};

#[test]
fn accepts_valid_keys_verbatim() {
    for key in [
        "a",
        "a/b",
        "dir/sub/dir/file.txt",
        "k/",
        "dir/",
        "with space.txt",
        "test$file.text",
        "ключ",
        "键/值",
        ".hidden",
        "a-b_c.d~e",
        // 空白不是控制字符，S3 允许；本 crate 不做 trim，原样保留。
        "   ",
        "x".repeat(MAX_OBJECT_KEY_BYTES).as_str(),
    ] {
        let parsed = ObjectKey::new(key).unwrap_or_else(|error| panic!("`{key}` 应合法: {error}"));
        assert_eq!(
            parsed.as_str(),
            key,
            "键内容必须原样保留（不做 trim 或改写）"
        );
        assert_eq!(parsed.to_string(), key);
        assert_eq!(AsRef::<str>::as_ref(&parsed), key);
    }
}

#[test]
fn rejects_empty_leading_slash_traversal_and_control_chars() {
    let cases: [(&str, &str); 7] = [
        ("", "空键"),
        ("/leading", "前导斜杠"),
        ("/", "单个斜杠"),
        ("../escape", "路径穿越"),
        ("dir/../escape", "路径穿越"),
        ("..name", "含 `..` 片段"),
        ("a\0b", "NUL 控制字符"),
    ];
    for (key, reason) in cases {
        let error = ObjectKey::new(key).expect_err(reason);
        assert!(matches!(error, S3Error::InvalidObjectKey(_)), "{error:?}");
        assert!(!error.is_retryable(), "对象键错误不可重试");
    }

    // 其它控制字符（换行、制表、DEL、C1）。
    for key in ["a\nb", "a\tb", "a\rb", "a\u{7f}b", "a\u{85}b"] {
        assert!(
            matches!(ObjectKey::new(key), Err(S3Error::InvalidObjectKey(_))),
            "`{key}` 必须被拒绝"
        );
    }
}

#[test]
fn enforces_utf8_byte_length_limit() {
    // ASCII：正好 1024 通过，1025 拒绝。
    assert!(ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES)).is_ok());
    let too_long = ObjectKey::new("x".repeat(MAX_OBJECT_KEY_BYTES + 1)).expect_err("超长必须拒绝");
    assert!(too_long.to_string().contains("1024"), "{too_long}");

    // 多字节字符按 UTF-8 字节数计算：341 * 3 = 1023 通过，342 * 3 = 1026 拒绝。
    assert!(ObjectKey::new("键".repeat(341)).is_ok());
    assert!(ObjectKey::new("键".repeat(342)).is_err());
    // 4 字节字符：256 * 4 = 1024 通过。
    assert!(ObjectKey::new("😀".repeat(256)).is_ok());
    assert!(ObjectKey::new("😀".repeat(257)).is_err());
}

#[test]
fn supports_conversions_equality_and_hashing() {
    use std::collections::HashSet;

    let key = ObjectKey::try_from("a/b").expect("TryFrom<&str> 应成功");
    assert_eq!(key, ObjectKey::new("a/b").expect("合法键"));
    assert!(ObjectKey::try_from("../x").is_err());

    let mut set = HashSet::new();
    set.insert(key.clone());
    set.insert(ObjectKey::new("a/b").expect("合法键"));
    assert_eq!(set.len(), 1, "相同键必须哈希相等");
    set.insert(ObjectKey::new("a/c").expect("合法键"));
    assert_eq!(set.len(), 2);

    let debug = format!("{key:?}");
    assert!(debug.contains("ObjectKey"), "{debug}");
}
