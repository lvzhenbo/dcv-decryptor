use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use pssh_box::{ToBytes, WIDEVINE_SYSTEM_ID, find_boxes_stream};
use std::fs::File;
use std::io::{Read, Take};

pub fn get_pssh(file_path: &str) -> Result<String> {
    // 以流式方式打开文件
    let file = File::open(file_path).context(format!("无法打开文件: {}", file_path))?;

    // 只读取文件的前 10MB，PSSH box 通常在文件开头
    let limited_file: Take<File> = file.take(10 * 1024 * 1024);

    // 使用 find_boxes_stream 以流式方式查找 PSSH boxes
    // pssh-box v0.2.1+ 已修复栈溢出问题,不再需要手动创建大栈空间的线程
    for result in find_boxes_stream(limited_file) {
        let pssh_box = result.context("解析PSSH box失败")?;

        if pssh_box.system_id == WIDEVINE_SYSTEM_ID {
            // 获取 PSSH data 并转换为字节
            let pssh_bytes = pssh_box.pssh_data.to_bytes();
            return Ok(BASE64.encode(&pssh_bytes));
        }
    }

    anyhow::bail!("未找到Widevine PSSH")
}
