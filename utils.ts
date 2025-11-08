import path from "path";

// 判断process.argv0是否包含bun.exe
export const isBun = process.argv0.includes("bun.exe");

export const currentPath = isBun ? "" : path.dirname(process.argv0);

export const USER_AGENT =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) " +
  "AppleWebKit/537.36 (KHTML, like Gecko) " +
  "DMMPlayerv2/2.4.0 " +
  "Chrome/120.0.6099.227 Electron/28.2.0 Safari/537.36";

const createExecutable = (name: string, isDir: boolean = false) => ({
  name,
  isDir,
  dirPath: currentPath ? path.join(currentPath, name) : `./${name}`,
});

export const executables = [
  createExecutable("ffmpeg.exe"),
  createExecutable("mp4dump.exe"),
  createExecutable("mp4decrypt.exe"),
  createExecutable("private_key.pem"),
  createExecutable("client_id.bin"),
];
