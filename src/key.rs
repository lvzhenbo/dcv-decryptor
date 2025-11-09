use anyhow::{Context, Result};
use reqwest::Client;
use rsa::RsaPrivateKey;
use rsa::pkcs1::DecodeRsaPrivateKey;
use std::fs;
use widevine::device::{DeviceType, SecurityLevel};
use widevine::{Cdm, Device, KeyType, LicenseType, Pssh};

use crate::utils::USER_AGENT;

#[derive(Debug, Clone)]
pub struct Key {
    pub kid: String,
    pub key: String,
}

pub async fn get_keys(
    pssh: &str,
    privatekey_path: &str,
    clientid_path: &str,
    license_uid: &str,
) -> Result<Vec<Key>> {
    // 解析 PSSH
    let pssh_data = Pssh::from_b64(pssh).context("解析PSSH失败")?;

    // 读取私钥和客户端ID
    let private_key_pem = fs::read_to_string(privatekey_path).context("读取私钥文件失败")?;
    let client_id = fs::read(clientid_path).context("读取客户端ID文件失败")?;

    // 解析 RSA 私钥
    let private_key = RsaPrivateKey::from_pkcs1_pem(&private_key_pem).context("解析私钥失败")?;

    // 创建 Widevine 设备
    let device = Device::new(
        DeviceType::CHROME,
        SecurityLevel::L3,
        private_key,
        &client_id,
    )
    .context("创建Widevine设备失败")?;

    // 创建 CDM
    let cdm = Cdm::new(device);

    // 创建会话并获取许可证请求
    let session = cdm.open();

    let request = session
        .get_license_request(pssh_data, LicenseType::STREAMING)
        .context("创建许可证请求失败")?;

    let challenge = request.challenge().context("获取challenge失败")?;

    // 发送许可证请求
    let client = Client::new();
    let license_response = client
        .post("https://mlic.dmm.com/drm/widevine/license")
        .header("User-Agent", USER_AGENT)
        .header("Host", "mlic.dmm.com")
        .header("Cookie", format!("licenseUID={}", license_uid))
        .header("Content-Type", "application/octet-stream")
        .body(challenge.to_vec())
        .send()
        .await
        .context("获取许可证失败")?;

    let license_data = license_response
        .bytes()
        .await
        .context("读取许可证响应失败")?;

    // 解析许可证获取密钥
    let keys_set = request.get_keys(&license_data).context("解析许可证失败")?;

    // 获取所有 CONTENT 类型的密钥
    let keys = keys_set
        .of_type(KeyType::CONTENT)
        .map(|k| Key {
            kid: hex::encode(&k.kid),
            key: hex::encode(&k.key),
        })
        .collect();

    Ok(keys)
}
