import { execFile } from "node:child_process";
import { randomUUID, timingSafeEqual } from "node:crypto";
import {
  chmod,
  mkdir,
  readFile,
  rename,
  writeFile,
} from "node:fs/promises";
import http from "node:http";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

const execute = promisify(execFile);
const BODY_LIMIT = 16 * 1024;
const OUTPUT_LIMIT = 16 * 1024;
const MAX_SESSION_MS = 4 * 60 * 60 * 1_000;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,191}$/;
const NODE_ID = /^(?:node\/[^/]*\/)?[A-Za-z0-9@$_-]{16,192}$/;
const VIEWS = ["desktop", "terminal", "files"];

export class BrokerError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

function exactObject(value, keys) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new BrokerError("Invalid request");
  }
  const actual = Object.keys(value);
  if (
    actual.length !== keys.length ||
    actual.some((key) => !keys.includes(key))
  ) {
    throw new BrokerError("Invalid request");
  }
  return value;
}

function exactHttpsOrigin(value, label) {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash
    ) {
      throw new Error("invalid");
    }
    return url.origin;
  } catch {
    throw new Error(`${label} must be an exact HTTPS origin`);
  }
}

function absoluteFile(value, label) {
  if (!value || !path.isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
  return value;
}

export async function readBrokerConfig(env = process.env) {
  const tokenFile = absoluteFile(env.BROKER_TOKEN_FILE, "BROKER_TOKEN_FILE");
  const token = (await readFile(tokenFile, "utf8")).trim();
  if (token.length < 32 || token.length > 2_048 || /\s/.test(token)) {
    throw new Error("Broker token is invalid");
  }
  const port = Number(env.BROKER_PORT || 4310);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new Error("BROKER_PORT is invalid");
  }
  const meshLoginUser = String(env.MESH_LOGIN_USER || "").trim();
  if (!ID.test(meshLoginUser)) throw new Error("MESH_LOGIN_USER is invalid");
  return {
    token,
    port,
    meshOrigin: exactHttpsOrigin(env.MESH_ORIGIN, "MESH_ORIGIN"),
    embedOrigin: exactHttpsOrigin(
      env.MESH_EMBED_ORIGIN || env.MESH_ORIGIN,
      "MESH_EMBED_ORIGIN",
    ),
    meshLoginUser,
    meshLoginPasswordFile: absoluteFile(
      env.MESH_LOGIN_PASSWORD_FILE,
      "MESH_LOGIN_PASSWORD_FILE",
    ),
    meshCtrlPath: absoluteFile(env.MESHCTRL_PATH, "MESHCTRL_PATH"),
    deviceMapFile: absoluteFile(env.DEVICE_MAP_FILE, "DEVICE_MAP_FILE"),
    stateFile: absoluteFile(env.BROKER_STATE_FILE, "BROKER_STATE_FILE"),
  };
}

export function parseSessionRequest(input, now = Date.now()) {
  const value = exactObject(input, [
    "schemaVersion",
    "supportSessionId",
    "gatewayId",
    "deviceKeyId",
    "operator",
    "capabilities",
    "expiresAt",
  ]);
  const operator = exactObject(value.operator, ["id", "name"]);
  if (
    value.schemaVersion !== 1 ||
    ![value.supportSessionId, value.gatewayId, value.deviceKeyId, operator.id].every(
      (candidate) => typeof candidate === "string" && ID.test(candidate),
    ) ||
    typeof operator.name !== "string" ||
    operator.name.length < 1 ||
    operator.name.length > 120 ||
    !Array.isArray(value.capabilities) ||
    value.capabilities.length !== VIEWS.length ||
    new Set(value.capabilities).size !== VIEWS.length ||
    VIEWS.some((view) => !value.capabilities.includes(view))
  ) {
    throw new BrokerError("Invalid request");
  }
  const requestedExpiry = new Date(value.expiresAt);
  if (
    !Number.isFinite(requestedExpiry.getTime()) ||
    requestedExpiry.toISOString() !== value.expiresAt ||
    requestedExpiry.getTime() <= now + 10_000
  ) {
    throw new BrokerError("Invalid request");
  }
  return {
    supportSessionId: value.supportSessionId,
    gatewayId: value.gatewayId,
    deviceKeyId: value.deviceKeyId,
    operator: { id: operator.id, name: operator.name },
    expiresAt: new Date(
      Math.min(requestedExpiry.getTime(), now + MAX_SESSION_MS),
    ),
  };
}

function validBearer(header, expected) {
  if (typeof header !== "string" || !header.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(header.slice(7));
  const required = Buffer.from(expected);
  return supplied.length === required.length && timingSafeEqual(supplied, required);
}

async function loadDevice(config, gatewayId, deviceKeyId) {
  const document = JSON.parse(await readFile(config.deviceMapFile, "utf8"));
  exactObject(document, ["schemaVersion", "devices"]);
  if (document.schemaVersion !== 1 || !Array.isArray(document.devices)) {
    throw new Error("Device map is invalid");
  }
  const matches = document.devices.filter(
    (device) =>
      device &&
      device.gatewayId === gatewayId &&
      device.deviceKeyId === deviceKeyId &&
      device.enabled === true,
  );
  if (matches.length !== 1 || !NODE_ID.test(String(matches[0].nodeId))) {
    throw new BrokerError("Managed device is not enrolled", 404);
  }
  return matches[0].nodeId;
}

async function loadState(config) {
  try {
    const document = JSON.parse(await readFile(config.stateFile, "utf8"));
    if (
      !document ||
      document.schemaVersion !== 1 ||
      !Array.isArray(document.sessions)
    ) {
      throw new Error("invalid");
    }
    return document;
  } catch (error) {
    if (error?.code === "ENOENT") return { schemaVersion: 1, sessions: [] };
    throw new Error("Broker state is invalid");
  }
}

async function saveState(config, document) {
  await mkdir(path.dirname(config.stateFile), { recursive: true });
  const temporary = `${config.stateFile}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(document)}\n`, {
    encoding: "utf8",
    mode: 0o600,
  });
  await chmod(temporary, 0o600);
  await rename(temporary, config.stateFile);
}

async function runMeshCtrl(config, args) {
  const { stdout } = await execute(
    process.execPath,
    [
      config.meshCtrlPath,
      ...args,
      "--url",
      config.meshOrigin.replace(/^https:/, "wss:"),
      "--tlsstrict",
      "--loginuser",
      config.meshLoginUser,
      "--loginpassfile",
      config.meshLoginPasswordFile,
    ],
    {
      timeout: 15_000,
      maxBuffer: OUTPUT_LIMIT,
      windowsHide: true,
      env: { PATH: process.env.PATH, NODE_ENV: "production" },
    },
  );
  return stdout;
}

function normalizeShareUrl(value, allowedOrigins, embedOrigin) {
  const url = new URL(value);
  if (
    !allowedOrigins.includes(url.origin) ||
    url.protocol !== "https:" ||
    url.username ||
    url.password ||
    url.hash ||
    !url.pathname.endsWith("/sharing") ||
    !url.searchParams.get("c")
  ) {
    throw new Error("MeshCentral returned an invalid share");
  }
  return new URL(`${url.pathname}${url.search}`, `${embedOrigin}/`).toString();
}

function createdShareLines(output) {
  return String(output)
    .replaceAll("\r", "")
    .trim()
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean);
}

function parseCreatedShareId(lines) {
  const idLine = lines.find((line) => line.startsWith("ID: "));
  const shareId = idLine?.slice(4);
  // MeshCentral 1.2.5 generates exactly 9 random bytes encoded as 12 base64
  // characters, replacing "/" with "@". Keep this strict and version-bound.
  if (!shareId || !/^[A-Za-z0-9+@]{12}$/.test(shareId)) {
    throw new Error("MeshCentral returned an invalid share");
  }
  return shareId;
}

export function parseCreatedShare(output, meshOrigin, embedOrigin = meshOrigin) {
  const lines = createdShareLines(output);
  const shareId = parseCreatedShareId(lines);
  const urlLine = lines.find((line) => line.startsWith("URL: "));
  if (!urlLine) throw new Error("MeshCentral returned an invalid share");
  const url = normalizeShareUrl(urlLine.slice(5), [meshOrigin], embedOrigin);
  return { shareId, url };
}

function publicSession(session, config) {
  return {
    sessionId: session.sessionId,
    expiresAt: session.expiresAt,
    views: Object.fromEntries(
      Object.entries(session.views).map(([view, url]) => [
        view,
        normalizeShareUrl(
          url,
          [config.meshOrigin, config.embedOrigin],
          config.embedOrigin,
        ),
      ]),
    ),
  };
}

export function createBrokerService(config, options = {}) {
  const run = options.runMeshCtrl || ((args) => runMeshCtrl(config, args));
  const clock = options.now || (() => Date.now());
  let lock = Promise.resolve();

  const serialized = (operation) => {
    const result = lock.then(operation, operation);
    lock = result.catch(() => undefined);
    return result;
  };

  async function removeShares(nodeId, shareIds) {
    let failure;
    for (const shareId of Object.values(shareIds)) {
      try {
        await run([
          "DeviceSharing",
          "--id",
          nodeId,
          "--remove",
          shareId,
        ]);
      } catch (error) {
        failure = error;
      }
    }
    if (failure) throw failure;
  }

  async function createSession(raw) {
    return serialized(async () => {
      const now = clock();
      const input = parseSessionRequest(raw, now);
      const nodeId = await loadDevice(
        config,
        input.gatewayId,
        input.deviceKeyId,
      );
      const state = await loadState(config);
      state.sessions = state.sessions.filter(
        (session) => Date.parse(session.expiresAt) > now,
      );
      const existing = state.sessions.find(
        (session) =>
          session.supportSessionId === input.supportSessionId &&
          session.gatewayId === input.gatewayId &&
          session.deviceKeyId === input.deviceKeyId &&
          session.operatorId === input.operator.id,
      );
      if (existing) return publicSession(existing, config);

      const stale = state.sessions.filter(
        (session) => session.supportSessionId === input.supportSessionId,
      );
      for (const session of stale) {
        await removeShares(session.nodeId, session.shareIds);
      }
      state.sessions = state.sessions.filter(
        (session) => session.supportSessionId !== input.supportSessionId,
      );

      const shareIds = {};
      const views = {};
      const guestBase = `C360 ${input.operator.name}`
        .replace(/[^A-Za-z0-9 ._@-]/g, "")
        .slice(0, 80);
      try {
        for (const view of VIEWS) {
          const output = await run([
            "DeviceSharing",
            "--id",
            nodeId,
            "--add",
            `${guestBase} ${view}`,
            "--type",
            view,
            "--consent",
            "notify",
            "--start",
            new Date(now).toISOString(),
            "--end",
            input.expiresAt.toISOString(),
          ]);
          // Record the provider ID before validating its returned URL. If URL
          // validation fails, the catch block can still revoke the new share.
          shareIds[view] = parseCreatedShareId(createdShareLines(output));
          const created = parseCreatedShare(
            output,
            config.meshOrigin,
            config.embedOrigin,
          );
          views[view] = created.url;
        }
      } catch (error) {
        await removeShares(nodeId, shareIds).catch(() => undefined);
        throw error;
      }

      const session = {
        sessionId: randomUUID(),
        supportSessionId: input.supportSessionId,
        gatewayId: input.gatewayId,
        deviceKeyId: input.deviceKeyId,
        operatorId: input.operator.id,
        nodeId,
        expiresAt: input.expiresAt.toISOString(),
        views,
        shareIds,
      };
      state.sessions.push(session);
      await saveState(config, state);
      return publicSession(session, config);
    });
  }

  async function revokeSession(supportSessionId) {
    return serialized(async () => {
      if (!ID.test(supportSessionId)) throw new BrokerError("Invalid session");
      const state = await loadState(config);
      const sessions = state.sessions.filter(
        (session) => session.supportSessionId === supportSessionId,
      );
      if (sessions.length === 0) throw new BrokerError("Session not found", 404);
      for (const session of sessions) {
        await removeShares(session.nodeId, session.shareIds);
      }
      state.sessions = state.sessions.filter(
        (session) => session.supportSessionId !== supportSessionId,
      );
      await saveState(config, state);
    });
  }

  return { createSession, revokeSession };
}

async function jsonBody(request) {
  const declared = Number(request.headers["content-length"] || 0);
  if (declared > BODY_LIMIT) throw new BrokerError("Request too large", 413);
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > BODY_LIMIT) throw new BrokerError("Request too large", 413);
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new BrokerError("Invalid JSON");
  }
}

function send(response, status, body) {
  const payload = body === undefined ? "" : `${JSON.stringify(body)}\n`;
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(payload),
    "x-content-type-options": "nosniff",
  });
  response.end(payload);
}

export function createHttpServer(config, service) {
  return http.createServer(async (request, response) => {
    try {
      if (request.method === "GET" && request.url === "/health") {
        send(response, 200, { status: "ok" });
        return;
      }
      if (!validBearer(request.headers.authorization, config.token)) {
        throw new BrokerError("Unauthorized", 401);
      }
      if (request.method === "POST" && request.url === "/v1/sessions") {
        send(response, 201, await service.createSession(await jsonBody(request)));
        return;
      }
      const match = request.url?.match(
        /^\/v1\/sessions\/by-support-session\/([A-Za-z0-9._:@-]+)$/,
      );
      if (request.method === "DELETE" && match) {
        await service.revokeSession(match[1]);
        send(response, 204);
        return;
      }
      throw new BrokerError("Not found", 404);
    } catch (error) {
      const status = error instanceof BrokerError ? error.status : 500;
      send(response, status, {
        error: status >= 500 ? "Managed support unavailable" : error.message,
      });
    }
  });
}

const isMain =
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const config = await readBrokerConfig();
  const service = createBrokerService(config);
  const server = createHttpServer(config, service);
  server.listen(config.port, "0.0.0.0", () => {
    console.log(`Managed support broker listening on port ${config.port}`);
  });
}
