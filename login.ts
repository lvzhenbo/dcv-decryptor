import axios from "axios";
import { jwtDecode, type JwtPayload } from "jwt-decode";
import { USER_AGENT } from "./utils";

interface JwtInfo extends JwtPayload {
  user_id: string;
}

export async function getUserId(email: string, password: string) {
  const response = await axios.post(
    "https://gw.dmmapis.com/connect/v1/token",
    {
      grant_type: "password",
      email: email,
      password: password,
    },
    {
      headers: {
        "user-agent": USER_AGENT,
        authorization:
          "Basic Vm5WaEhseTQyMERhSzE2bkFvMkMyOkNoYXZKRFlMcW12OXg3SkxxUk9aU1dBUGpMOGV4cHVV",
      },
    }
  );

  const encoded = response.data.body.id_token;
  const info: JwtInfo = jwtDecode(encoded);
  return info.user_id;
}

export async function getLicenseUid(userId: string) {
  const response = await axios.post(
    "https://www.dmm.com/service/digitalapi/digital/-/get_license_uid",
    {
      oid: userId,
    },
    {
      headers: {
        "user-agent": USER_AGENT,
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );
  return response.data.license_uid;
}
