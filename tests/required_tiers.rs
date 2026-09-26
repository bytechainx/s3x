#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! 验收：六层测试入口文件必须存在且带机器可识别标记。

const ROOT: &str = env!("CARGO_MANIFEST_DIR");

fn must_contain(rel: &str, needles: &[&str]) {
    let text = std::fs::read_to_string(format!("{ROOT}/{rel}")).unwrap_or_else(|e| {
        panic!("{rel} 必须存在：{e}");
    });
    for needle in needles {
        assert!(text.contains(needle), "{rel} 必须包含标记 {needle:?}");
    }
}

#[test]
fn required_test_tiers_are_present() {
    must_contain("tests/tdd_contracts.rs", &["TDD-PROBE:"]);
    must_contain("tests/sdd_spec.rs", &["SPEC-MAP:"]);
    must_contain("tests/object_key.rs", &["fn "]);
    must_contain("tests/sigv4_vectors.rs", &["fn "]);
    must_contain("tests/http_methods.rs", &["fn "]);
    must_contain("tests/config_env.rs", &["fn "]);
    must_contain("benches/hot_path.rs", &["fn main"]);
    must_contain("tests/e2e_s3.rs", &["E2E_MANIFEST"]);
    must_contain("tests/live_s3.rs", &["#[ignore"]);
    must_contain("Cargo.toml", &["[[bench]]", "hot_path"]);
}
