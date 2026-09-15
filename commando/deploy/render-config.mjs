import { chmod, readFile, writeFile } from "node:fs/promises";

function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

const host = required("SUPPORT_CONSOLE_HOST");
if (!/^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])$/.test(host)) {
  throw new Error("SUPPORT_CONSOLE_HOST is invalid");
}
const origins = required("PLATFORM_FRAMING_ORIGINS")
  .split(",")
  .map((value) => new URL(value.trim()))
  .map((url) => {
    if (
      url.protocol !== "https:" ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      url.username ||
      url.password
    ) {
      throw new Error("PLATFORM_FRAMING_ORIGINS contains an invalid origin");
    }
    return url.origin;
  });
const username = required("MONGO_USERNAME");
const password = required("MONGO_PASSWORD");
const sessionKey = (
  await readFile("/run/secrets/mesh-session-key", "utf8")
).trim();
if (sessionKey.length < 64) throw new Error("Mesh session key is too short");

const config = {
  $schema:
    "https://raw.githubusercontent.com/Ylianst/MeshCentral/master/meshcentral-config-schema.json",
  settings: {
    cert: host,
    WANonly: true,
    sessionKey,
    port: 8443,
    aliasPort: 443,
    redirPort: 0,
    tlsOffload: "172.29.0.2",
    trustedProxy: "172.29.0.2",
    selfUpdate: false,
    allowFraming: true,
    allowedFramingOrigins: origins,
    webRTC: false,
    lockAgentDownload: true,
    mongoDb: `mongodb://${encodeURIComponent(username)}:${encodeURIComponent(password)}@mongo:27017/meshcentral?authSource=admin`,
    autoBackup: {
      backupPath: "/opt/meshcentral/meshcentral-backups",
      backupIntervalHours: 24,
      keepLastDaysBackup: 14,
    },
  },
  domains: {
    "": {
      title: "Commando360 Managed Support",
      title2: "Authorized company systems only",
      // This source-built image does not generate MeshCentral's optional
      // `*-min.js` web assets. Enabling minification makes invite pages point
      // at missing files and remain hidden after load.
      minify: false,
      newAccounts: false,
      userNameIsEmail: false,
      certUrl: `https://${host}:443`,
      guestDeviceSharing: { maxSessionTime: 240 },
    },
  },
};

await writeFile("/data/config.json", `${JSON.stringify(config, null, 2)}\n`, {
  mode: 0o600,
});
await chmod("/data/config.json", 0o600);
