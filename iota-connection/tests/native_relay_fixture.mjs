// Capture the unchanged pinned SDK, not a Rust reconstruction of its frame.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../..",
);
const clientRoot = path.join(root, "client");
const sdkRoot = path.join(clientRoot, "node_modules/mtp");
const { mtp, hashPackageInputs } = await import(
  pathToFileURL(path.join(sdkRoot, "dist/vite/index.js")).href
);
const typeMapsPath = path.join(clientRoot, "mtp-type-maps/type-maps.yaml");
const wasmRoot =
  process.env.RELAY_CLIENT_WASM_DIR ??
  (await fs.mkdtemp("/tmp/opencode/chat-secret-wasm-"));
if (!process.env.RELAY_CLIENT_WASM_DIR) {
  process.env.TMPDIR = "/tmp/opencode";
  await mtp({ typeMaps: typeMapsPath, outDir: wasmRoot }).config(
    { root: "/tmp/opencode" },
    { command: "serve" },
  );
}
const typeMapSource = await fs.readFile(typeMapsPath, "utf8");
const packageRoot = await fs.realpath(sdkRoot);
const packageInputs = await hashPackageInputs();
const stamp = JSON.parse(
  await fs.readFile(path.join(wasmRoot, ".mtp-build.json"), "utf8"),
);
assert(
  [false, true].some(
    (release) =>
      stamp.fingerprint ===
      createHash("sha256")
        .update(
          JSON.stringify({
            packageRoot,
            packageInputs,
            typeMapsPath,
            typeMapSource,
            release,
            wasmPackArgs: [],
          }),
        )
        .digest("hex"),
  ),
  "WASM cache does not match the pinned package and application type map; rebuild it outside client/",
);
const sandbox = await fs.mkdtemp("/tmp/opencode/chat-secret-sdk-");
await fs.cp(path.join(sdkRoot, "dist"), path.join(sandbox, "dist"), {
  recursive: true,
});
await fs.cp(path.join(sdkRoot, "type-map"), path.join(sandbox, "type-map"), {
  recursive: true,
});
await fs.copyFile(
  path.join(sdkRoot, "package.json"),
  path.join(sandbox, "package.json"),
);
await fs.cp(wasmRoot, path.join(sandbox, "bindings/wasm/pkg"), {
  recursive: true,
});
// Match the two aliases installed by the pinned mtp/vite plugin.
await fs.copyFile(
  path.join(wasmRoot, "mtp_type_map.js"),
  path.join(sandbox, "dist/type-map/index.js"),
);
const sdkUrl = pathToFileURL(path.join(sandbox, "dist/sdk/index.js")).href;
const raw = await import(
  pathToFileURL(path.join(sandbox, "dist/raw/index.js")).href
);
const wasm = await fs.readFile(path.join(wasmRoot, "mtp_wasm_bg.wasm"));
raw.initSync({ module: wasm });
const sdk = await import(sdkUrl);
const typescript = (
  await import(
    pathToFileURL(
      path.join(clientRoot, "node_modules/typescript/lib/typescript.js"),
    ).href
  )
).default;
const wrappingSource = await fs.readFile(
  path.join(clientRoot, "packages/crypto/src/chatSecret.ts"),
  "utf8",
);
const wrappingModule = typescript.transpileModule(
  wrappingSource.replace('from "mtp"', `from ${JSON.stringify(sdkUrl)}`),
  {
    compilerOptions: {
      target: typescript.ScriptTarget.ES2022,
      module: typescript.ModuleKind.ESNext,
    },
  },
).outputText;
const wrapping = await import(
  `data:text/javascript;base64,${Buffer.from(wrappingModule).toString("base64")}`
);
const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const bundle = (keyring) => {
  const key = raw.WasmKeyring.from_bytes(keyring);
  const publicKey = key.public_key_bundle();
  try {
    return publicKey.to_bytes();
  } finally {
    publicKey.free();
    key.free();
  }
};
const users = [sdk.crypto.generateKeyring(), sdk.crypto.generateKeyring()];
const nodes = [sdk.crypto.generateKeyring(), sdk.crypto.generateKeyring()];
const secret = wrapping.randomChatSecret();
const chatId = wrapping.deriveChatId(11, 22);
const secretId = wrapping.deriveChatSecretId(chatId);
const copies = await Promise.all(
  users.map((keyring) =>
    wrapping.wrapChatSecret({
      chatSecret: secret,
      recipientKemPublicKey: wrapping.ownKemPublicKeyFromKeyring(b64(keyring)),
      chatId,
      secretId,
      version: 1,
    }),
  ),
);
for (const [index, copy] of copies.entries()) {
  const context = {
    ...copy,
    keyring: b64(users[index]),
    chatId,
    secretId,
    version: 1,
  };
  assert.deepEqual(await wrapping.unwrapChatSecret(context), secret);
  await assert.rejects(() =>
    wrapping.unwrapChatSecret({ ...context, chatId: "principal:renamed" }),
  );
  await assert.rejects(() =>
    wrapping.unwrapChatSecret({
      ...context,
      secretId: "chat:principal:renamed:main",
    }),
  );
}
const client = await sdk.MTPClient.create({
  url: "https://example.invalid",
  pings: false,
  logging: false,
});
const frames = [];
client.raw.client.send = async (frame) => frames.push(frame.slice());
await client.sendSealedRelay(
  "SetChatSecret",
  {
    ChatId: chatId,
    SecretId: secretId,
    VersionNumber: 1,
    WrappingScheme: copies[0].wrappingScheme,
    CreatedAt: Date.now(),
    Recipients: copies.map((copy, index) => ({
      UserId: String(index === 0 ? 11 : 22),
      EncryptedSecret: copy.encryptedSecret,
      KemCiphertext: copy.kemCiphertext,
    })),
  },
  {
    identity: { signerId: 11n, keyring: users[0] },
    nextHop: { kind: "iota", id: 101n },
    finalRecipientId: 22n,
    metadataRecipients: nodes.map(bundle),
    contentRecipients: nodes.map(bundle),
  },
);
assert.equal(frames.length, 1);
const packageJson = JSON.parse(
  await fs.readFile(path.join(clientRoot, "package.json"), "utf8"),
);
const fixture = {
  producer: "pinned-MTPClient.sendSealedRelay",
  sdk: packageJson.dependencies.mtp,
  wasmSha256: createHash("sha256").update(wasm).digest("hex"),
  packageInputsSha256: packageInputs,
  typeMapSha256: createHash("sha256").update(typeMapSource).digest("hex"),
  wrappingSourceSha256: createHash("sha256")
    .update(wrappingSource)
    .digest("hex"),
  frame: b64(frames[0]),
  signerPublicKey: b64(bundle(users[0])),
  nodeKeys: nodes.map(b64),
  chatId,
  secretId,
  encryptedSecrets: copies.map((copy) => b64(copy.encryptedSecret)),
  kemCiphertexts: copies.map((copy) => b64(copy.kemCiphertext)),
};
const output = process.argv[2];
assert(output, "Pass an output fixture path");
await fs.writeFile(output, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(
  `Captured ${fixture.sdk}. Both original Client unwraps passed; renamed namespaces failed.`,
);
