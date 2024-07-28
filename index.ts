import boxen from "boxen";
import fs from "fs";
import { $ } from "bun";
import { input } from "@inquirer/prompts";
import { confirm } from "@inquirer/prompts";
import ora from "ora";
import { getPssh } from "./pssh";
import { executables } from "./utils";
import { getUserId, getLicenseUid } from "./login";
import { getKeys } from "./key";
import { cmd } from "./cmd";

console.log(
  boxen(
    "1. 本项目只是个人学习使用Bun.js制作命令行程序之作，不支持盗版。\n2. 本项目不提供CDM，相关问题请自己处理。\n3. 一切因使用者所导致的法律问题与本项目无关。",
    {
      title: "免责声明",
      titleAlignment: "center",
      borderStyle: "round",
    }
  )
);

const agree = await confirm({
  message: "是否同意免责声明？",
  default: false,
});

if (!agree) {
  process.exit(0);
}

for (const executable of executables) {
  try {
    await $`${executable.name} -version`.quiet();
  } catch (envError) {
    if (fs.existsSync(executable.name)) {
      executable.isDir = true;
    } else {
      console.error(`${executable.name} 未在环境变量和当前目录中找到。`);
      process.exit(1);
    }
  }
}

const opt = cmd();

if (!opt.privatekey) {
  if (!fs.existsSync("private_key.pem")) {
    console.error("请将private_key.pem放在当前目录中");
    process.exit(1);
  }
}

if (!opt.clientid) {
  if (!fs.existsSync("client_id.bin")) {
    console.error("请将client_id.bin放在当前目录中");
    process.exit(1);
  }
}

if (!opt.email) {
  opt.email = await input({
    message: "请输入邮箱",
    required: true,
    validate: (value) =>
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/.test(
        value
      ) || "请输入有效的邮箱地址",
  });
}

if (!opt.password) {
  opt.password = await input({
    message: "请输入密码",
    required: true,
  });
}

if (!opt.file) {
  opt.file = await input({
    message: "请输入DCV文件路径",
    required: true,
    validate: (value) => value.endsWith(".dcv") || "请输入正确的DCV文件路径",
  });
}

const data = {
  licenseUid: "",
  pssh: "",
  privatekey: opt.privatekey || "private_key.pem",
  clientid: opt.clientid || "client_id.bin",
};

const loginOra = ora("正在获取licenseUid").start();
try {
  const userId = await getUserId(opt.email, opt.password);
  data.licenseUid = await getLicenseUid(userId);
  loginOra.succeed("licenseUid获取成功");
  // console.log(data.licenseUid);
} catch (error) {
  loginOra.fail("licenseUid获取失败");
  console.error(error);
  process.exit(1);
}

const psshOra = ora("正在获取PSSH").start();
try {
  data.pssh = await getPssh(opt.file);
  psshOra.succeed("PSSH获取成功");
  // console.log(data.pssh);
} catch (error) {
  psshOra.fail("PSSH获取失败");
  console.error(error);
  process.exit(1);
}

const keyOra = ora("正在获取密钥").start();

let ks = [];

try {
  const keys = await getKeys(data);
  keyOra.succeed("密钥获取成功");
  ks = keys.flatMap((item) =>
    item ? ["--key", `${item.kid}:${item.key}`] : []
  );
} catch (error) {
  keyOra.fail("密钥获取失败");
  console.error(error);
  process.exit(1);
}

const decryptOra = ora("正在解密").start();

try {
  const mp4decrypt = Bun.spawn([
    executables[2].isDir ? "./mp4decrypt.exe" : "mp4decrypt",
    ...ks,
    opt.file,
    opt.file.replace(".dcv", ".tmp"),
  ]);
  await mp4decrypt.exited;
  if (mp4decrypt.exitCode !== 0) {
    throw new Error(
      `mp4decrypt process exited with code ${mp4decrypt.exitCode}`
    );
  }
  decryptOra.succeed("解密成功");
} catch (error) {
  decryptOra.fail("解密失败");
  console.error(error);
  process.exit(1);
}

const ffmpegOra = ora("正在转换").start();

try {
  await $`ffmpeg -i ${opt.file.replace(".dcv", ".tmp")} -c copy ${opt.file.replace(".dcv", ".mp4")}`.quiet();
  ffmpegOra.succeed("转换成功");
} catch (error) {
  ffmpegOra.fail("转换失败");
  console.error(error);
  process.exit(1);
}
