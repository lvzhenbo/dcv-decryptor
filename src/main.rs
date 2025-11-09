mod key;
mod login;
mod pssh;
mod utils;

use anyhow::{Context, Result};
use boxen::{BorderStyle, TitleAlignment, builder};
use clap::Parser;
use inquire::{Confirm, Text};
use loading::Loading;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser, Debug)]
#[command(name = "dcv-decryptor")]
#[command(about = "DCV文件解密工具", version)]
struct Args {
    /// DCV文件路径
    #[arg(value_name = "FILE")]
    file: Option<String>,

    /// 登录邮箱
    #[arg(short, long)]
    email: Option<String>,

    /// 登录密码
    #[arg(long, alias = "pw")]
    password: Option<String>,

    /// privatekey路径
    #[arg(long, alias = "pk")]
    privatekey: Option<String>,

    /// clientid路径
    #[arg(long, alias = "ci")]
    clientid: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 显示免责声明
    let disclaimer = "1. 本项目只是个人学习使用Rust制作命令行程序之作，不支持盗版。\n\
                     2. 本项目不提供CDM，相关问题请自己处理。\n\
                     3. 一切因使用者所导致的法律问题与本项目无关。";

    let boxed = builder()
        .border_style(BorderStyle::Round)
        .title("免责声明")
        .title_alignment(TitleAlignment::Center)
        .render(disclaimer)
        .unwrap();

    println!("{}", boxed);
    println!();

    // 询问是否同意免责声明
    let agree = Confirm::new("是否同意免责声明？")
        .with_default(false)
        .prompt()?;

    if !agree {
        println!("已取消操作。");
        return Ok(());
    }

    let mut args = Args::parse();

    // 检查必需的可执行文件
    check_executables()?;

    // 获取程序所在目录
    let exe_dir = env::current_exe()
        .context("无法获取程序路径")?
        .parent()
        .context("无法获取程序目录")?
        .to_path_buf();

    // 验证文件存在
    let privatekey = args
        .privatekey
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| exe_dir.join("private_key.pem"));
    let clientid = args
        .clientid
        .clone()
        .map(PathBuf::from)
        .unwrap_or_else(|| exe_dir.join("client_id.bin"));

    if !privatekey.exists() {
        anyhow::bail!("请将private_key.pem放在程序所在目录中");
    }
    if !clientid.exists() {
        anyhow::bail!("请将client_id.bin放在程序所在目录中");
    }

    // 转换为字符串路径以便后续使用
    let privatekey_str = privatekey
        .to_str()
        .context("私钥路径包含无效字符")?
        .to_string();
    let clientid_str = clientid
        .to_str()
        .context("客户端ID路径包含无效字符")?
        .to_string();

    // 获取或验证输入参数
    if args.email.is_none() {
        args.email = Some(
            Text::new("请输入邮箱")
                .with_validator(|input: &str| {
                    if utils::validate_email(input) {
                        Ok(inquire::validator::Validation::Valid)
                    } else {
                        Ok(inquire::validator::Validation::Invalid(
                            "请输入有效的邮箱地址".into(),
                        ))
                    }
                })
                .prompt()?,
        );
    }

    if args.password.is_none() {
        args.password = Some(Text::new("请输入密码").prompt()?);
    }

    if args.file.is_none() {
        args.file = Some(
            Text::new("请输入DCV文件路径")
                .with_validator(|input: &str| {
                    if input.ends_with(".dcv") {
                        Ok(inquire::validator::Validation::Valid)
                    } else {
                        Ok(inquire::validator::Validation::Invalid(
                            "请输入正确的DCV文件路径".into(),
                        ))
                    }
                })
                .prompt()?,
        );
    }

    let email = args.email.unwrap();
    let password = args.password.unwrap();
    let file_path = args.file.unwrap();

    // 获取 licenseUid
    let loading = create_spinner("正在获取licenseUid");
    let user_id = login::get_user_id(&email, &password)
        .await
        .context("获取用户ID失败")?;
    let license_uid = login::get_license_uid(&user_id)
        .await
        .context("获取licenseUid失败")?;
    loading.success("licenseUid获取成功");
    loading.end();

    // 获取 PSSH
    let loading = create_spinner("正在获取PSSH");
    let pssh = pssh::get_pssh(&file_path).context("获取PSSH失败")?;
    loading.success("PSSH获取成功");
    loading.end();

    // 获取密钥
    let loading = create_spinner("正在获取密钥");
    let keys = key::get_keys(&pssh, &privatekey_str, &clientid_str, &license_uid)
        .await
        .context("获取密钥失败")?;
    loading.success("密钥获取成功");
    loading.end();

    // 解密
    let loading = create_spinner("正在解密");
    let tmp_file = file_path.replace(".dcv", ".tmp");
    let mut cmd = Command::new("mp4decrypt");

    for key in &keys {
        cmd.arg("--key").arg(format!("{}:{}", key.kid, key.key));
    }

    cmd.arg(&file_path).arg(&tmp_file);

    let output = cmd.output().context("执行mp4decrypt失败")?;
    if !output.status.success() {
        // 失败时显示错误信息
        eprintln!(
            "\nmp4decrypt stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!("mp4decrypt解密失败");
    }
    loading.success("解密成功");
    loading.end();

    // 转换格式
    let loading = create_spinner("正在转换");
    let output_file = file_path.replace(".dcv", ".mp4");
    let output = Command::new("ffmpeg")
        .args(["-i", &tmp_file, "-c", "copy", &output_file])
        .output()
        .context("执行ffmpeg失败")?;

    if !output.status.success() {
        // 失败时显示错误信息
        eprintln!(
            "\nffmpeg stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        anyhow::bail!("ffmpeg转换失败");
    }
    loading.success("转换成功");
    loading.end();

    // 清理临时文件
    let _ = fs::remove_file(&tmp_file);

    println!("✓ 处理完成！输出文件: {}", output_file);

    Ok(())
}

fn check_executables() -> Result<()> {
    let executables = ["ffmpeg", "mp4decrypt"];

    for exe in executables {
        if Command::new(exe).arg("-version").output().is_err() {
            anyhow::bail!("{} 未在环境变量中找到", exe);
        }
    }

    Ok(())
}

fn create_spinner(msg: &str) -> Loading {
    let loading = Loading::default();
    loading.text(msg);
    loading
}
