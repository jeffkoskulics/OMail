/* Multi-device linking E2E (see docs/concepts.md): an already-authenticated
 * device mints a short-lived link and uploads an encrypted parcel; a second,
 * unauthenticated browser context fetches and decrypts it locally, then
 * registers its own credential bound to the SAME identity. Proves the vault
 * (and hence the identity) carries over, not just a cosmetic login. */
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

  const devA = await newIdentity("devA");
  await devA.goto(base + "/");
  await devA.click("#btn-register");
  await devA.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
  const upaA = (await devA.textContent("#welcome-upa")).trim();
  await devA.click("#welcome-continue");
  await devA.waitForSelector("#mailbox-view:not(.hidden)");

  await devA.click("#btn-devices");
  await devA.waitForSelector("#devices-overlay:not(.hidden)");
  const before = await devA.locator("#devices-list li").count();
  console.log("credentials before linking:", before);

  await devA.click("#btn-link-device");
  await devA.waitForSelector("#link-result:not(.hidden)", { timeout: 15000 });
  const linkUrl = (await devA.textContent("#link-url")).trim();
  console.log("link url minted:", linkUrl.includes("#link="));
  await devA.click("#devices-close");

  // Device B has no identity yet; it only has the link.
  const devB = await newIdentity("devB");
  await devB.goto(linkUrl);
  await devB.waitForSelector("#link-claim-view:not(.hidden)", { timeout: 15000 });
  await devB.click("#btn-linkclaim-passkey");
  await devB.waitForSelector("#mailbox-view:not(.hidden)", { timeout: 20000 });
  const upaB = (await devB.textContent("#me-upa")).trim();
  console.log("same identity on the new device:", upaA === upaB);
  if (upaA !== upaB) throw new Error(`UPA mismatch: ${upaA} vs ${upaB}`);

  // Prove the vault genuinely carried over (not just a cosmetic session):
  // Device B can independently mint a new relationship invite.
  await devB.click("#btn-create-invite");
  await devB.waitForSelector("#invite-overlay:not(.hidden)");
  await devB.fill("#invite-label", "Bob");
  await devB.click("#invite-mint");
  await devB.waitForSelector("#invite-result:not(.hidden)", { timeout: 15000 });
  console.log("device B vault is fully functional (minted an invite)");

  // Back on device A, the new credential is now listed (renderDevicesList
  // fetches asynchronously after the click event fires, so wait for it).
  await devA.click("#btn-devices");
  await devA.waitForSelector("#devices-overlay:not(.hidden)");
  await devA.waitForFunction(
    (expected) => document.querySelectorAll("#devices-list li").length >= expected,
    before + 1,
    { timeout: 10000 },
  );
  const after = await devA.locator("#devices-list li").count();
  console.log("credentials after linking:", after);
  if (after !== before + 1) {
    throw new Error(`Expected ${before + 1} credentials, got ${after}`);
  }

  await browser.close();
  console.log("DEVICE-LINK E2E OK");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
