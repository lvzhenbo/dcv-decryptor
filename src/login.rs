use anyhow::{Context, Result};
use jsonwebtoken::dangerous::insecure_decode;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::utils::USER_AGENT;

#[derive(Debug, Serialize, Deserialize)]
struct TokenResponse {
    body: TokenBody,
}

#[derive(Debug, Serialize, Deserialize)]
struct TokenBody {
    id_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Claims {
    user_id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct LicenseUidResponse {
    license_uid: String,
}

pub async fn get_user_id(email: &str, password: &str) -> Result<String> {
    let client = Client::new();

    let response = client
        .post("https://gw.dmmapis.com/connect/v1/token")
        .header("User-Agent", USER_AGENT)
        .header(
            "Authorization",
            "Basic Vm5WaEhseTQyMERhSzE2bkFvMkMyOkNoYXZKRFlMcW12OXg3SkxxUk9aU1dBUGpMOGV4cHVV",
        )
        .json(&json!({
            "grant_type": "password",
            "email": email,
            "password": password,
        }))
        .send()
        .await
        .context("发送登录请求失败")?;

    let token_response: TokenResponse = response.json().await.context("解析登录响应失败")?;

    // 使用 jsonwebtoken 解码 JWT (不验证签名)
    // 参考: https://github.com/Keats/jsonwebtoken/issues/124#issuecomment-2369633417
    // 手动替换 JWT header 以避免解析问题
    const DEBUG_JWT_HEADER: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9";

    let token = &token_response.body.id_token;
    let mut parts: Vec<&str> = token.splitn(3, '.').collect();
    if parts.len() >= 2 {
        parts[0] = DEBUG_JWT_HEADER;
    }
    let token_with_header = parts.join(".");

    let token_data = insecure_decode::<Claims>(&token_with_header).context("解码JWT失败")?;

    Ok(token_data.claims.user_id)
}

pub async fn get_license_uid(user_id: &str) -> Result<String> {
    let client = Client::new();

    let params = [("oid", user_id)];

    let response = client
        .post("https://www.dmm.com/service/digitalapi/digital/-/get_license_uid")
        .header("User-Agent", USER_AGENT)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .form(&params)
        .send()
        .await
        .context("发送获取license_uid请求失败")?;

    let license_response: LicenseUidResponse =
        response.json().await.context("解析license_uid响应失败")?;

    Ok(license_response.license_uid)
}
