import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  BrokerError,
  createBrokerService,
  parseCreatedShare,
  parseSessionRequest,
} from "./server.mjs";

const now = Date.parse("2026-09-14T18:00:00.000Z");
const supportSessionId = "67f5c5c7-16ec-46d0-81af-395488727f67";

function request(overrides = {}) {
  return {
    schemaVersion: 1,
    supportSessionId,
    gatewayId: "gateway-poc-001",
    deviceKeyId: "device-key-001",
    operator: { id: "admin-001", name: "Support Operator" },
    capabilities: ["desktop", "terminal", "files"],
    expiresAt: "2026-09-15T06:00:00.000Z",
    ...overrides,
  };
}

async function fixture() {
  const directory = await mkdtemp(path.join(os.tmpdir(), "c360-broker-"));
  const deviceMapFile = path.join(directory, "devices.json");
  const stateFile = path.join(directory, "state.json");
  await writeFile(
    deviceMapFile,
    JSON.stringify({
      schemaVersion: 1,
      devices: [
        {
          gatewayId: "gateway-poc-001",
          deviceKeyId: "device-key-001",
          nodeId: "node//0123456789abcdef",
          enabled: true,
        },
      ],
    }),
  );
  return {
    config: {
      meshOrigin: "https://support.commando360.ai",
      embedOrigin: "https://ai-services.sphinx-balance.ts.net:8443",
      meshLoginUser: "commando-broker",
      meshLoginPasswordFile: "/run/secrets/mesh-login-password",
      meshCtrlPath: "/app/meshctrl.js",
      deviceMapFile,
      stateFile,
    },
    stateFile,
  };
}

test("request validation caps provider sessions at four hours", () => {
  assert.equal(
    parseSessionRequest(request(), now).expiresAt.toISOString(),
    "2026-09-14T22:00:00.000Z",
  );
  assert.throws(
    () => parseSessionRequest(request({ capabilities: ["desktop"] }), now),
    BrokerError,
  );
});

test("the broker CLI path retains strict certificate and hostname validation", async () => {
  const meshCtrl = await readFile(
    fileURLToPath(new URL("../../meshctrl.js", import.meta.url)),
    "utf8",
  );
  assert.match(meshCtrl, /args\.tlsstrict === true/);
  assert.match(meshCtrl, /\? \{ rejectUnauthorized: true \}/);
  assert.match(meshCtrl, /args\.loginpassfile != null/);
  assert.match(meshCtrl, /--guestsharing\s+- Allow creation and removal of device guest shares/);
  assert.equal(
    (meshCtrl.match(/args\.guestsharing\) \{ meshrights \|= 524288; \}/g) ?? []).length,
    2,
    "group and device assignments must expose only the native guest-sharing right",
  );
});

test("the deployment initializes broker state for the non-root runtime", async () => {
  const compose = await readFile(
    fileURLToPath(new URL("../deploy/compose.yaml", import.meta.url)),
    "utf8",
  );
  assert.match(compose, /broker-state-init:/);
  assert.match(compose, /chown 100:101 \/state && chmod 0700 \/state/);
  assert.match(compose, /broker-state-init:\n\s+condition: service_completed_successfully/);
  assert.match(compose, /MESH_EMBED_ORIGIN: \$\{SUPPORT_PRIVATE_CONSOLE_ORIGIN:\?required\}/);
});

test("share parsing validates the MeshCentral origin and returns the private console origin", () => {
  assert.deepEqual(
    parseCreatedShare(
      "ID: Abcdef+Gh@12\nURL: https://support.commando360.ai/sharing?c=token\n",
      "https://support.commando360.ai",
      "https://ai-services.sphinx-balance.ts.net:8443",
    ),
    {
      shareId: "Abcdef+Gh@12",
      url: "https://ai-services.sphinx-balance.ts.net:8443/sharing?c=token",
    },
  );
  assert.throws(() =>
    parseCreatedShare(
      "ID: Abcdef+Gh@12\nURL: https://attacker.example/sharing?c=token\n",
      "https://support.commando360.ai",
      "https://ai-services.sphinx-balance.ts.net:8443",
    ),
  );
});

test("the public console exposes only agents while Tailscale receives the UI", async () => {
  const caddy = await readFile(
    fileURLToPath(new URL("../deploy/Caddyfile", import.meta.url)),
    "utf8",
  );
  const renderConfig = await readFile(
    fileURLToPath(new URL("../deploy/render-config.mjs", import.meta.url)),
    "utf8",
  );
  const webserver = await readFile(
    fileURLToPath(new URL("../../webserver.js", import.meta.url)),
    "utf8",
  );
  assert.match(caddy, /remote_ip 172\.29\.0\.4\/32/);
  assert.match(caddy, /reverse_proxy http:\/\/meshcentral:8444/);
  assert.match(caddy, /http:\/\/:8080/);
  assert.match(renderConfig, /agentPort: 8444/);
  assert.match(renderConfig, /guestShareOrigin: privateConsole\.origin/);
  assert.match(webserver, /guestShareOrigin must be an exact HTTPS origin/);
  assert.match(webserver, /obj\.guestShareTarget\.hostname/);
});

test("one approved session creates least-privilege shares and revokes all of them", async () => {
  const { config, stateFile } = await fixture();
  const calls = [];
  let sequence = 0;
  const service = createBrokerService(config, {
    now: () => now,
    runMeshCtrl: async (args) => {
      calls.push(args);
      if (args.includes("--remove")) return "OK\n";
      sequence += 1;
      return `ID: Abcdef+Gh@0${sequence}\nURL: https://support.commando360.ai/sharing?c=token${sequence}\n`;
    },
  });

  const session = await service.createSession(request());
  assert.equal(session.expiresAt, "2026-09-14T22:00:00.000Z");
  assert.equal(
    session.views.desktop,
    "https://ai-services.sphinx-balance.ts.net:8443/sharing?c=token1",
  );
  assert.deepEqual(Object.keys(session.views), ["desktop", "terminal", "files"]);
  assert.deepEqual(
    calls.slice(0, 3).map((args) => args[args.indexOf("--type") + 1]),
    ["desktop", "terminal", "files"],
  );
  assert.equal(calls.every((args) => !args.includes("desktop,terminal,files")), true);

  const repeated = await service.createSession(request());
  assert.deepEqual(repeated, session);
  assert.equal(calls.length, 3, "idempotent retry must not create more shares");

  await service.revokeSession(supportSessionId);
  assert.equal(calls.filter((args) => args.includes("--remove")).length, 3);
  assert.equal(JSON.parse(await readFile(stateFile, "utf8")).sessions.length, 0);
});

test("a rejected provider URL still revokes the created share", async () => {
  const { config } = await fixture();
  const calls = [];
  const service = createBrokerService(config, {
    now: () => now,
    runMeshCtrl: async (args) => {
      calls.push(args);
      if (args.includes("--remove")) return "OK\n";
      return "ID: Abcdef+Gh@12\nURL: https://attacker.example/sharing?c=token\n";
    },
  });

  await assert.rejects(service.createSession(request()), /invalid share/);
  const removal = calls.find((args) => args.includes("--remove"));
  assert.ok(removal);
  assert.equal(removal[removal.indexOf("--remove") + 1], "Abcdef+Gh@12");
});

test("a copied Gateway identifier cannot select a differently commissioned device key", async () => {
  const { config } = await fixture();
  const service = createBrokerService(config, {
    now: () => now,
    runMeshCtrl: async () => {
      throw new Error("must not execute");
    },
  });
  await assert.rejects(
    service.createSession(request({ deviceKeyId: "copied-key" })),
    /not enrolled/,
  );
});
