/* Browser E2E for the device-key fallback: a browser with NO WebAuthn
 * (window.PublicKeyCredential removed, as in Tor Browser) registers with
 * a device key, chats with the host, then reloads and signs back in. */
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || undefined,
  });
  const context = await browser.newContext();
  // Simulate Tor Browser: WebAuthn entirely absent.
  await context.addInitScript(() => {
    delete window.PublicKeyCredential;
    delete navigator.credentials;
  });
  const page = await context.newPage();
  page.on("dialog", (dialog) => dialog.accept());
  page.on("pageerror", (err) => console.log("[pageerror]", err.message));

  const base = process.env.OMAIL_URL || "http://localhost:8000";
  await page.goto(base + "/");

  // Fallback CTA must be revealed, passkey buttons disabled
  await page.waitForSelector("#fallback-cta:not(.hidden)");
  console.log("fallback visible:", await page.locator("#btn-register-device").isVisible());
  console.log("passkey disabled:", await page.locator("#btn-register").isDisabled());

  // Register with a device key (confirm() auto-accepted above)
  await page.click("#btn-register-device");
  await page.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
  const upa = await page.textContent("#welcome-upa");
  console.log("welcome UPA:", upa);
  await page.click("#welcome-continue");

  // Mailbox works: chat with the Administrator over the triple ratchet
  await page.waitForSelector("#mailbox-view:not(.hidden)");
  await page.waitForSelector("#compose:not(.hidden)");
  await page.fill("#compose-input", "ping");
  await page.click("#compose button");
  await page.waitForSelector(".msg.in", { timeout: 15000 });
  console.log("host reply:", await page.textContent(".msg.in"));

  // Reload → sign back in with the same device key from localStorage
  await page.reload();
  await page.waitForSelector("#fallback-cta:not(.hidden)");
  await page.click("#btn-login-device");
  await page.waitForSelector("#mailbox-view:not(.hidden)", { timeout: 20000 });
  const upaAfter = await page.textContent("#me-upa");
  console.log("same identity after reload:", upaAfter === upa);
  if (upaAfter !== upa) throw new Error("identity changed across device-key login");

  await browser.close();
  console.log("DEVICE-KEY E2E OK");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
