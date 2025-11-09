use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use pssh_box::{ToBytes, WIDEVINE_SYSTEM_ID, find_boxes_stream};
use std::fs::File;
use std::io::{Read, Take};
use std::thread;

pub fn get_pssh(file_path: &str) -> Result<String> {
    let file_path = file_path.to_string();

    // 使用更大的栈空间来避免栈溢出（16MB）
    let handle = thread::Builder::new()
        .stack_size(16 * 1024 * 1024)
        .spawn(move || -> Result<String> {
            // 以流式方式打开文件
            let file = File::open(&file_path).context(format!("无法打开文件: {}", file_path))?;

            // 只读取文件的前 10MB，PSSH box 通常在文件开头
            let limited_file: Take<File> = file.take(10 * 1024 * 1024);

            // 使用 find_boxes_stream 以流式方式查找 PSSH boxes
            let mut widevine_pssh = None;

            for result in find_boxes_stream(limited_file) {
                let pssh_box = result.context("解析PSSH box失败")?;

                if pssh_box.system_id == WIDEVINE_SYSTEM_ID && widevine_pssh.is_none() {
                    // 获取 PSSH data 并转换为字节
                    let pssh_bytes = pssh_box.pssh_data.to_bytes();
                    widevine_pssh = Some(BASE64.encode(&pssh_bytes));
                    // 找到 Widevine PSSH 后就可以停止搜索了
                    break;
                }
            }

            match widevine_pssh {
                Some(pssh) => Ok(pssh),
                None => anyhow::bail!("未找到Widevine PSSH"),
            }
        })
        .context("创建线程失败")?;

    handle
        .join()
        .map_err(|e| anyhow::anyhow!("线程执行失败: {:?}", e))?
}
