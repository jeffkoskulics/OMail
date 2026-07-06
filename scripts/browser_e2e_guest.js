/* Guest hosting E2E (see docs/concepts.md): Alice mints a guest invite for
 * Charlie, who claims it with a passkey in a fresh browser context. Proves
 * the claimed account keeps the exact UPA Alice minted, behaves like any
 * tenant (Administrator chat works), and that the invite is single-use. */
const { chromium } = require("playwright");

const PRF_AUTH = {
  protocol: "ctap2", ctap2Version: "ctap2_1", transport: "internal",
  hasResidentKey: true, hasUserVerification: true, hasPrf: true,
  isUserVerified: true, automaticPresenceSimulation: true,
};

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || undefined,
  });
  const base = process.env.OMAIL_URL || "http://localhost:8000";

  async function newIdentity(name) {
    const ctx = await browser.newContext();
    const page = await ctx.newPage();
    page.on("dialog", (d) => d.accept());
    page.on("pageerror", (e) => console.log(`[${name} pageerror]`, e.message));
    const cdp = await ctx.newCDPSession(page);
    await cdp.send("WebAuthn.enable");
    await cdp.send("WebAuthn.addVirtualAuthenticator", { options: PRF_AUTH });
    return page;
  }

  // Alice registers and mints a guest invite for Charlie
  const alice = await newIdentity("alice");
  await alice.goto(base + "/");
  await alice.click("#btn-register");
  await alice.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
  await alice.click("#welcome-continue");
  await alice.waitForSelector("#mailbox-view:not(.hidden)");

  await alice.click("#btn-invite-guest");
  await alice.waitForSelector("#guest-overlay:not(.hidden)");
  await alice.fill("#guest-label", "Charlie");
  await alice.click("#guest-mint");
  await alice.waitForSelector("#guest-result:not(.hidden)", { timeout: 15000 });
  const claimUrl = (await alice.textContent("#guest-upa")).trim();
  console.log("claim url minted:", claimUrl.includes("?claim="));
  await alice.click("#guest-close");

  // Charlie opens the claim link cold (no prior identity) and sets up a passkey
  const charlie = await newIdentity("charlie");
  await charlie.goto(claimUrl);
  await charlie.waitForSelector("#claim-view:not(.hidden)", { timeout: 15000 });
  await charlie.click("#btn-claim-passkey");
  await charlie.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
  const charlieUpa = (await charlie.textContent("#welcome-upa")).trim();
  const expectedUpa = decodeURIComponent(claimUrl.split("?claim=")[1]);
  console.log("claimed account kept the minted UPA:", charlieUpa === expectedUpa);
  if (charlieUpa !== expectedUpa) {
    throw new Error(`UPA mismatch: claimed ${charlieUpa}, expected ${expectedUpa}`);
  }
  await charlie.click("#welcome-continue");
  await charlie.waitForSelector("#mailbox-view:not(.hidden)");

  // Charlie is now an ordinary tenant: Administrator chat works
  await charlie.fill("#compose-input", "ping");
  await charlie.click("#compose button");
  await charlie.waitForSelector(".msg.in", { timeout: 15000 });
  console.log("charlie admin reply:", await charlie.textContent(".msg.in"));

  // The invite is single-use: re-opening the same claim link must fail
  await charlie.goto(claimUrl);
  await charlie.waitForSelector("#claim-view:not(.hidden)", { timeout: 15000 });
  await charlie.click("#btn-claim-passkey");
  await charlie.waitForFunction(
    () => document.querySelector("#claim-status").textContent.includes("already"),
    { timeout: 10000 },
  );
  console.log("reclaim correctly rejected:", await charlie.textContent("#claim-status"));

  await browser.close();
  console.log("GUEST E2E OK");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
