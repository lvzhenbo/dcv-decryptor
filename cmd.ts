import { program } from "commander";
import { version } from "./package.json";

export const cmd = () => {
  let file = "";

  program.name("dcv-decryptor").description("可能有用的玩意").version(version);

  program
    .argument("[file]", "")
    .description("[file]: DCV文件路径")
    .action((str) => {
      file = str;
    });

  program.option("-e, --email <email>", "登录邮箱");
  program.option("--pw, --password <password>", "登录密码");
  program.option("--pk, --privatekey <privatekey>", "privatekey路径");
  program.option("--ci, --clientid <clientid>", "clientid路径");

  program.parse();

  const options: {
    email?: string;
    password?: string;
    privatekey?: string;
    clientid?: string;
    file?: string;
  } = { ...program.opts(), file };

  return options;
};
