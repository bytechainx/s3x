//! 配置校验、环境变量解析、secret 脱敏与 `effective_endpoint`。

use std::time::Duration;

use s3x::{
    S3Config, S3ConfigBuilder, S3Error, DEFAULT_REGION, ENV_ACCESS_KEY_ID, ENV_ACCESS_KEY_SECRET,
    ENV_BUCKET, ENV_CONNECT_TIMEOUT_MS, ENV_ENDPOINT, ENV_FORCE_PATH_STYLE, ENV_MAX_IN_FLIGHT,
    ENV_MAX_RETRIES, ENV_REGION, ENV_REQUEST_TIMEOUT_MS, ENV_SESSION_TOKEN, ENV_USER_AGENT,
    HARD_MAX_IN_FLIGHT, HARD_MAX_REQUEST_TIMEOUT_MS, HARD_MAX_RETRIES,
};

/// `from_env` 读取进程级环境变量；同一测试二进制内必须串行。
static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

const ALL_ENV: [&str; 12] = [
    ENV_ENDPOINT,
    ENV_REGION,
    ENV_BUCKET,
    ENV_ACCESS_KEY_ID,
    ENV_ACCESS_KEY_SECRET,
    ENV_SESSION_TOKEN,
    ENV_FORCE_PATH_STYLE,
    ENV_REQUEST_TIMEOUT_MS,
    ENV_CONNECT_TIMEOUT_MS,
    ENV_MAX_RETRIES,
    ENV_MAX_IN_FLIGHT,
    ENV_USER_AGENT,
];

fn env_guard() -> std::sync::MutexGuard<'static, ()> {
    ENV_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn clear_env() {
    for name in ALL_ENV {
        std::env::remove_var(name);
    }
}

fn valid_config() -> S3Config {
    S3Config::builder()
        .bucket("examplebucket")
        .access_key_id("AKIDEXAMPLE")
        .access_key_secret("secret")
        .build()
        .expect("测试配置必须有效")
}

#[test]
fn defaults_and_effective_endpoint() {
    let config = S3Config::default();
    assert!(config.endpoint.is_none());
    assert_eq!(config.region, DEFAULT_REGION);
    assert!(!config.force_path_style);
    assert!(config.session_token.is_none());
    assert_eq!(
        config.effective_endpoint(),
        "https://s3.us-east-1.amazonaws.com"
    );

    // 自定义 endpoint 去掉尾部斜杠；全空白视为未配置。
    let custom = S3Config {
        endpoint: Some("https://minio.example.com:9000/".to_owned()),
        ..S3Config::default()
    };
    assert_eq!(
        custom.effective_endpoint(),
        "https://minio.example.com:9000"
    );
    let blank = S3Config {
        endpoint: Some("   ".to_owned()),
        ..valid_config()
    };
    assert_eq!(
        blank.effective_endpoint(),
        "https://s3.us-east-1.amazonaws.com"
    );
    assert!(blank.validate().is_ok(), "全空白 endpoint 视为未配置");

    // 换区域后官方端点跟随变化。
    let other_region = S3Config {
        region: "ap-southeast-2".to_owned(),
        ..valid_config()
    };
    assert_eq!(
        other_region.effective_endpoint(),
        "https://s3.ap-southeast-2.amazonaws.com"
    );
}

#[test]
fn validate_accepts_and_rejects_expected_configs() {
    assert!(valid_config().validate().is_ok());

    // region 规则。
    let mut bad_regions: Vec<String> = ["", "US-East-1", "-bad", "bad-", "us_east_1"]
        .iter()
        .map(|region| (*region).to_owned())
        .collect();
    bad_regions.push("a".repeat(65));
    for region in &bad_regions {
        let config = S3Config {
            region: region.clone(),
            ..valid_config()
        };
        let error = config.validate().expect_err("region 必须被拒绝");
        assert!(error.to_string().contains("region"), "{error}");
        assert!(!error.is_retryable());
    }
    for region in ["us-east-1", "eu-west-1", "cn-north-1", "a"] {
        let config = S3Config {
            region: region.to_owned(),
            ..valid_config()
        };
        assert!(config.validate().is_ok(), "region `{region}` 必须通过");
    }
    let longest_region = S3Config {
        region: "a".repeat(64),
        ..valid_config()
    };
    assert!(longest_region.validate().is_ok());

    // bucket 规则。
    let mut bad_buckets: Vec<String> = [
        "",
        "ab",
        "Example-Bucket",
        "-bucket",
        "bucket-",
        "a..b",
        "192.168.5.4",
        "bucket_underscore",
    ]
    .iter()
    .map(|bucket| (*bucket).to_owned())
    .collect();
    bad_buckets.push("b".repeat(64));
    for bucket in &bad_buckets {
        let config = S3Config {
            bucket: bucket.clone(),
            ..valid_config()
        };
        let error = config.validate().expect_err("bucket 必须被拒绝");
        assert!(error.to_string().contains("bucket"), "{error}");
    }
    for bucket in ["abc", "examplebucket", "example.bucket", "b-c-d"] {
        let config = S3Config {
            bucket: bucket.to_owned(),
            ..valid_config()
        };
        assert!(config.validate().is_ok(), "bucket `{bucket}` 必须通过");
    }
    let longest_bucket = S3Config {
        bucket: "b".repeat(63),
        ..valid_config()
    };
    assert!(longest_bucket.validate().is_ok());

    // endpoint 规则。
    for endpoint in [
        "ftp://example.com",
        "https://",
        "not a url",
        "https://example.com/base",
        "https://example.com/?a=1",
    ] {
        let config = S3Config {
            endpoint: Some(endpoint.to_owned()),
            ..valid_config()
        };
        let error = config.validate().expect_err("endpoint 必须被拒绝");
        assert!(
            error.to_string().contains("endpoint") || error.to_string().contains("URL"),
            "{error}"
        );
    }
    for endpoint in ["http://127.0.0.1:9000", "https://minio.example.com:9000"] {
        let config = S3Config {
            endpoint: Some(endpoint.to_owned()),
            ..valid_config()
        };
        assert!(config.validate().is_ok(), "endpoint `{endpoint}` 必须通过");
    }

    // 凭据与限额。
    let missing_secret = S3Config::builder()
        .bucket("examplebucket")
        .access_key_id("id")
        .build()
        .expect_err("缺少 secret 必须拒绝");
    assert!(matches!(missing_secret, S3Error::Config(_)));

    let blank_id = S3Config {
        access_key_id: "  ".to_owned(),
        ..valid_config()
    };
    assert!(blank_id.validate().is_err());

    let empty_token = S3Config {
        session_token: Some(String::new()),
        ..valid_config()
    };
    assert!(empty_token.validate().is_err());

    let zero_timeout = S3Config {
        request_timeout_ms: 0,
        ..valid_config()
    };
    assert!(zero_timeout.validate().is_err());
    let huge_timeout = S3Config {
        request_timeout_ms: HARD_MAX_REQUEST_TIMEOUT_MS + 1,
        ..valid_config()
    };
    assert!(huge_timeout.validate().is_err());

    let zero_retries = S3Config {
        max_retries: 0,
        ..valid_config()
    };
    assert!(zero_retries.validate().is_err());
    let too_many_retries = S3Config {
        max_retries: HARD_MAX_RETRIES + 1,
        ..valid_config()
    };
    assert!(too_many_retries.validate().is_err());

    let zero_in_flight = S3Config {
        max_in_flight: 0,
        ..valid_config()
    };
    assert!(zero_in_flight.validate().is_err());
    let too_many_in_flight = S3Config {
        max_in_flight: HARD_MAX_IN_FLIGHT + 1,
        ..valid_config()
    };
    assert!(too_many_in_flight.validate().is_err());

    let blank_agent = S3Config {
        user_agent: " ".to_owned(),
        ..valid_config()
    };
    assert!(blank_agent.validate().is_err());
}

#[test]
fn from_toml_parses_flat_fields_and_isolates_env() {
    let _guard = env_guard();
    clear_env();
    std::env::set_var(ENV_BUCKET, "from-env-bucket");

    let config = S3Config::from_toml(
        r#"
bucket = "from-toml-bucket"
region = "eu-central-1"
access_key_id = "AKIDEXAMPLE"
force_path_style = true
request_timeout_ms = 1500
connect_timeout_ms = 0
max_retries = 4
max_in_flight = 9
endpoint = "https://minio.example.com:9000"
user_agent = "custom/1"
"#,
    )
    .expect("TOML 解析必须成功");
    clear_env();

    assert_eq!(
        config.bucket, "from-toml-bucket",
        "from_toml 必须与环境变量隔离"
    );
    assert_eq!(config.region, "eu-central-1");
    assert_eq!(config.request_timeout_ms, 1500);
    assert_eq!(config.connect_timeout_ms, 0, "0 表示不单独限制连接超时");
    assert_eq!(config.max_retries, 4);
    assert_eq!(config.max_in_flight, 9);
    assert_eq!(config.user_agent, "custom/1");
    assert!(config.access_key_secret.is_empty(), "secret 不能来自 TOML");
    assert!(config.session_token.is_none());

    // 密钥与未知字段 fail-closed，且错误不回显取值。
    let secret_error =
        S3Config::from_toml("bucket = \"examplebucket\"\naccess_key_secret = \"hunter2\"\n")
            .expect_err("TOML 中的 secret 必须被拒绝");
    assert!(
        !secret_error.to_string().contains("hunter2"),
        "{secret_error}"
    );
    assert!(S3Config::from_toml("bucket = \"examplebucket\"\nsession_token = \"tok\"\n").is_err());
    assert!(S3Config::from_toml("bucket = \"examplebucket\"\nunknown = 1\n").is_err());
    assert!(S3Config::from_toml("this is not toml").is_err());

    // TOML 不携带密钥：结构校验通过，但完整校验仍要求凭据非空。
    let structural = S3Config::from_toml("bucket = \"examplebucket\"\naccess_key_id = \"id\"\n")
        .expect("结构合法");
    assert!(
        structural.validate().is_err(),
        "缺少 access_key_secret 时完整校验必须失败"
    );
}

#[test]
fn from_env_loads_and_validates() {
    let _guard = env_guard();
    clear_env();
    assert!(S3Config::from_env().is_err(), "缺少必填项必须 fail-closed");

    std::env::set_var(ENV_BUCKET, "examplebucket");
    std::env::set_var(ENV_ACCESS_KEY_ID, "AKIDEXAMPLE");
    std::env::set_var(ENV_ACCESS_KEY_SECRET, "secret-from-env");
    std::env::set_var(ENV_SESSION_TOKEN, "token-from-env");
    std::env::set_var(ENV_REGION, "ap-southeast-2");
    std::env::set_var(ENV_ENDPOINT, "https://minio.example.com:9000/");
    std::env::set_var(ENV_FORCE_PATH_STYLE, "on");
    std::env::set_var(ENV_REQUEST_TIMEOUT_MS, "2500");
    std::env::set_var(ENV_CONNECT_TIMEOUT_MS, "300");
    std::env::set_var(ENV_MAX_RETRIES, "5");
    std::env::set_var(ENV_MAX_IN_FLIGHT, "16");
    std::env::set_var(ENV_USER_AGENT, "custom-agent/1");

    let config = S3Config::from_env().expect("环境变量配置必须有效");

    // 非法数值只报告变量名。
    std::env::set_var(ENV_REQUEST_TIMEOUT_MS, "not-a-number");
    let parse_error = S3Config::from_env().expect_err("非法数值必须拒绝");
    std::env::set_var(ENV_FORCE_PATH_STYLE, "maybe");
    let bool_error = S3Config::from_env().expect_err("非法布尔值必须拒绝");
    clear_env();

    assert_eq!(config.bucket, "examplebucket");
    assert_eq!(config.region, "ap-southeast-2");
    assert_eq!(config.access_key_secret, "secret-from-env");
    assert_eq!(config.session_token.as_deref(), Some("token-from-env"));
    assert!(config.force_path_style);
    assert_eq!(config.request_timeout_ms, 2500);
    assert_eq!(config.connect_timeout_ms, 300);
    assert_eq!(config.max_retries, 5);
    assert_eq!(config.max_in_flight, 16);
    assert_eq!(config.user_agent, "custom-agent/1");
    assert_eq!(
        config.effective_endpoint(),
        "https://minio.example.com:9000"
    );

    assert!(
        parse_error.to_string().contains(ENV_REQUEST_TIMEOUT_MS),
        "{parse_error}"
    );
    assert!(
        !parse_error.to_string().contains("not-a-number"),
        "{parse_error}"
    );
    assert!(
        bool_error.to_string().contains(ENV_FORCE_PATH_STYLE),
        "{bool_error}"
    );
    assert!(!bool_error.to_string().contains("maybe"), "{bool_error}");
}

#[test]
fn debug_redacts_secret_and_session_token() {
    let config = S3Config::builder()
        .bucket("examplebucket")
        .access_key_id("AKIDEXAMPLE")
        .access_key_secret("super-secret-key")
        .session_token("super-secret-token")
        .build()
        .expect("配置有效");

    let rendered = format!("{config:?}");
    assert!(rendered.contains("***"), "{rendered}");
    assert!(!rendered.contains("super-secret-key"), "{rendered}");
    assert!(!rendered.contains("super-secret-token"), "{rendered}");
    // Access Key ID 不是密钥，保留以便排障。
    assert!(rendered.contains("AKIDEXAMPLE"), "{rendered}");

    // 无 session token 时渲染为 None（不泄露任何取值）。
    let without_token = S3Config::builder()
        .bucket("examplebucket")
        .access_key_id("AKIDEXAMPLE")
        .access_key_secret("secret")
        .build()
        .expect("配置有效");
    assert!(format!("{without_token:?}").contains("None"));
}

#[test]
fn builder_overrides_round_trip() {
    let config = S3ConfigBuilder::new()
        .bucket("examplebucket")
        .region("us-west-2")
        .access_key_id("AKIDEXAMPLE")
        .access_key_secret("secret")
        .session_token("token")
        .force_path_style(true)
        .request_timeout(Duration::from_millis(900))
        .connect_timeout(Some(Duration::from_millis(120)))
        .max_retries(2)
        .max_in_flight(4)
        .user_agent("agent/2")
        .build()
        .expect("构建必须成功");
    assert_eq!(config.request_timeout_ms, 900);
    assert_eq!(config.connect_timeout_ms, 120);
    assert_eq!(config.max_retries, 2);
    assert_eq!(config.max_in_flight, 4);

    let rebuilt = S3ConfigBuilder::from_config(config)
        .connect_timeout(None)
        .aws_endpoint()
        .build()
        .expect("重新构建");
    assert_eq!(rebuilt.connect_timeout_ms, 0);
    assert!(rebuilt.endpoint.is_none());
    assert_eq!(
        rebuilt.effective_endpoint(),
        "https://s3.us-west-2.amazonaws.com"
    );
}

#[test]
fn object_and_bucket_urls_follow_addressing_style() {
    let virtual_hosted = S3Config {
        bucket: "examplebucket".to_owned(),
        ..valid_config()
    };
    let key = s3x::ObjectKey::new("dir/a b.txt").expect("合法键");
    assert_eq!(
        virtual_hosted.object_url(&key),
        "https://examplebucket.s3.us-east-1.amazonaws.com/dir/a%20b.txt"
    );
    assert_eq!(
        virtual_hosted.bucket_url(),
        "https://examplebucket.s3.us-east-1.amazonaws.com/"
    );

    let path_style = S3Config {
        force_path_style: true,
        ..virtual_hosted.clone()
    };
    assert_eq!(
        path_style.object_url(&key),
        "https://s3.us-east-1.amazonaws.com/examplebucket/dir/a%20b.txt"
    );
    assert_eq!(
        path_style.bucket_url(),
        "https://s3.us-east-1.amazonaws.com/examplebucket"
    );
}
