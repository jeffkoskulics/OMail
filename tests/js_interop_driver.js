/*
 * Node driver for the JS<->Python Triple Ratchet interop test.
 *
 * Usage: node js_interop_driver.js <phase> <work_dir>
 *   phase "initiate": read bob_bundle.json, create a session, encrypt two
 *     messages -> writes js_envelopes.json (+ serialized alice state).
 *   phase "finish": read py_replies.json, decrypt both replies, send one
 *     more epoch-2 message -> writes js_final.json.
 */
const fs = require("fs");
const path = require("path");

const staticDir = path.join(__dirname, "..", "src", "omail", "static");
require(path.join(staticDir, "vendor.js"));
require(path.join(staticDir, "crypto.js"));
const C = globalThis.OMailCrypto;

const [, , phase, workDir] = process.argv;
const read = (name) => JSON.parse(fs.readFileSync(path.join(workDir, name)));
const write = (name, obj) =>
  fs.writeFileSync(path.join(workDir, name), JSON.stringify(obj));

(async () => {
  if (phase === "initiate") {
    const { bundle } = read("bob_bundle.json");
    const seed = C.randomBytes(32);
    const alice = await C.TripleRatchet.initiate(seed, bundle);
    const e1 = await alice.encrypt(new TextEncoder().encode("js->py message one"));
    const e2 = await alice.encrypt(new TextEncoder().encode("js->py message two"));
    write("js_envelopes.json", { e1, e2, alice_state: alice.toDict() });
  } else if (phase === "finish") {
    const alice = C.TripleRatchet.fromDict(read("js_envelopes.json").alice_state);
    const { r1, r2 } = read("py_replies.json");
    const p1 = new TextDecoder().decode(await alice.decrypt(r1));
    const p2 = new TextDecoder().decode(await alice.decrypt(r2));
    const e3 = await alice.encrypt(new TextEncoder().encode("js epoch-two"));
    write("js_final.json", { decrypted: [p1, p2], e3 });
  } else {
    throw new Error(`unknown phase: ${phase}`);
  }
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
