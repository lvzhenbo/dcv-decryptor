import path from "path";

// 判断process.argv0是否包含bun.exe
export const isBun = process.argv0.includes("bun.exe");

export const currentPath = process.argv0.includes("bun.exe")
  ? ""
  : path.dirname(process.argv0);

export const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "DMMPlayerv2/2.4.0 " +
  "Chrome/120.0.6099.227 Electron/28.2.0 Safari/537.36";

export const executables = [
  {
    name: "ffmpeg.exe",
    isDir: false,
    dirPath: path.join(currentPath, "ffmpeg.exe"),
  },
  {
    name: "mp4dump.exe",
    isDir: false,
    dirPath: path.join(currentPath, "mp4dump.exe"),
  },
  {
    name: "mp4decrypt.exe",
    isDir: false,
    dirPath: path.join(currentPath, "mp4decrypt.exe"),
  },
  {
    name: "private_key.pem",
    isDir: false,
    dirPath: path.join(currentPath, "private_key.pem"),
  },
  {
    name: "client_id.bin",
    isDir: false,
    dirPath: path.join(currentPath, "client_id.bin"),
  },
];
