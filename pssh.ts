import { executables } from "./utils";
import { $ } from "bun";

interface Mp4DumpInfo {
  name: string;
  children: Mp4DumpInfo[];
  system_id?: string;
  data?: string;
}
export async function getPssh(file: string) {
  // const mp4dump = Bun.spawn([
  //   "./mp4dump.exe",
  //   "--verbosity",
  //   "3",
  //   "--format",
  //   "json",
  //   file,
  // ]);
  // await mp4dump.exited;
  // if (mp4dump.exitCode !== 0) {
  //   throw new Error(`mp4dump process exited with code ${mp4dump.exitCode}`);
  // }

  const jsonInfo: Mp4DumpInfo[] = await $`${
    executables[1].isDir ? executables[1].dirPath : "mp4dump"
  } --verbosity 3 --format json ${file}`.json();
  // console.log(jsonInfo);

  const psshData = jsonInfo
    .find(({ name }) => name === "moov")
    ?.children.find(
      ({ system_id }) =>
        system_id === "[ed ef 8b a9 79 d6 4a ce a3 c8 27 dc d5 1d 21 ed]"
    )
    ?.data?.replace("[", "")
    .replace("]", "")
    .replace(/\s+/g, "");

  return psshData ? Buffer.from(psshData, "hex").toString("base64") : "";
}

/**
 * Convert MP4 PSSH to Widevine PSSH
 * @param {string} base64Pssh - Base64 encoded PSSH from MP4
 * @returns {string} - Base64 encoded Widevine PSSH
 */
export function convertToWidevinePssh(base64Pssh: string): string {
  const psshBuffer = Buffer.from(base64Pssh, "base64");

  // Widevine SystemID
  const widevineSystemId = Buffer.from([
    0xed, 0xef, 0x8b, 0xa9, 0x79, 0xd6, 0x4a, 0xce, 0xa3, 0xc8, 0x27, 0xdc,
    0xd5, 0x1d, 0x21, 0xed,
  ]);

  // Create Widevine PSSH box
  const psshBox = Buffer.concat([
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // Size (to be filled later)
    Buffer.from("pssh"), // 'pssh'
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // Version & Flags
    widevineSystemId, // Widevine SystemID
    Buffer.from([0x00, 0x00, 0x00, 0x00]), // Data size (to be filled later)
    psshBuffer,
  ]);

  // Fill in the size fields
  psshBox.writeUInt32BE(psshBox.length, 0); // Total size
  psshBox.writeUInt32BE(psshBuffer.length, 28); // Data size

  // Return base64 encoded Widevine PSSH
  return psshBox.toString("base64");
}
