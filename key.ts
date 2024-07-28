import axios from "axios";
import fs from "fs";
import {
  LicenseType,
  SERVICE_CERTIFICATE_CHALLENGE,
  Session,
} from "node-widevine";
import { USER_AGENT } from "./utils";
import { convertToWidevinePssh } from "./pssh";

interface Data {
  licenseUid: string;
  pssh: string;
  privatekey: string;
  clientid: string;
}

export async function getKeys(data: Data) {
  const pssh = Buffer.from(convertToWidevinePssh(data.pssh), "base64");
  const privateKey = fs.readFileSync(data.privatekey);
  const identifierBlob = fs.readFileSync(data.clientid);

  const session = new Session({ privateKey, identifierBlob }, pssh);
  const serviceCertificateResponse = await axios.post(
    "https://mlic.dmm.com/drm/widevine/license",
    Buffer.from(SERVICE_CERTIFICATE_CHALLENGE),
    {
      headers: {
        "Content-Type": "application/octet-stream",
      },
      responseType: "arraybuffer",
    }
  );
  const serviceCertificate = Buffer.from(serviceCertificateResponse.data);
  await session.setServiceCertificateFromMessage(serviceCertificate);

  const response = await axios.post(
    "https://mlic.dmm.com/drm/widevine/license",
    Buffer.from(session.createLicenseRequest(LicenseType.OFFLINE)),
    {
      headers: {
        "User-Agent": USER_AGENT,
        Host: "mlic.dmm.com",
        Cookie: `licenseUID=${data.licenseUid}`,
        "Content-Type": "application/octet-stream",
      },
      responseType: "arraybuffer",
    }
  );
  const keys = session.parseLicense(Buffer.from(response.data));

  return keys;
}
