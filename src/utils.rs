use regex::Regex;

pub const USER_AGENT: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) \
    DMMPlayerv2/2.4.0 \
    Chrome/120.0.6099.227 Electron/28.2.0 Safari/537.36";

pub fn validate_email(email: &str) -> bool {
    // 完整的邮箱验证正则表达式
    let email_regex = Regex::new(r#"^(([^<>()[\\]\\.,;:\s@"]+(\.[^<>()[\\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$"#).unwrap();

    email_regex.is_match(email)
}
