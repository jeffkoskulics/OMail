/* Browser E2E: passkey registration with PRF, welcome screen, host chat. */
const { chromium } = require("playwright");

(async () => {
  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || undefined,
  });
  const page = await browser.newPage();
  page.on("console", (msg) => {
    if (msg.type() === "error") console.log("[console.error]", msg.text());
  });
  page.on("pageerror", (err) => console.log("[pageerror]", err.message));

  // Virtual authenticator with PRF + resident keys + UV
  const cdp = await page.context().newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      ctap2Version: "ctap2_1",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      hasPrf: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  console.log("virtual authenticator:", authenticatorId);

  await page.goto((process.env.OMAIL_URL || "http://localhost:8000") + "/");
  console.log("title:", await page.title());
  console.log("banner visible:", await page.locator("#bookmark-banner").isVisible());

  // Register
  await page.click("#btn-register");
  await page.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
  const upa = await page.textContent("#welcome-upa");
  console.log("welcome UPA:", upa);
  console.log("welcome QR svg:", (await page.locator("#welcome-qr svg").count()) === 1);
  console.log("welcome onion:", await page.textContent("#welcome-onion"));
  await page.click("#welcome-continue");

  // Mailbox with Administrator contact auto-selected
  await page.waitForSelector("#mailbox-view:not(.hidden)");
  await page.waitForSelector("#contact-list li");
  console.log("first contact:", (await page.textContent("#contact-list li")).trim());

  // Chat with the host through the triple ratchet
  await page.waitForSelector("#compose:not(.hidden)");
  await page.fill("#compose-input", "ping");
  await page.click("#compose button");
  await page.waitForSelector(".msg.out", { timeout: 15000 });
  await page.waitForSelector(".msg.in", { timeout: 15000 });
  console.log("sent:", await page.textContent(".msg.out"));
  console.log("host reply:", await page.textContent(".msg.in"));

  await page.fill("#compose-input", "hello");
  await page.click("#compose button");
  await page.waitForFunction(() => document.querySelectorAll(".msg.in").length >= 2,
    null, { timeout: 15000 });
  const replies = await page.$$eval(".msg.in", (els) => els.map((e) => e.textContent));
  console.log("host reply 2:", replies[1]);

  // Reload -> passkey login -> archives decrypt
  await page.reload();
  await page.click("#btn-login");
  await page.waitForSelector("#mailbox-view:not(.hidden)", { timeout: 20000 });
  await page.waitForSelector(".msg.out", { timeout: 15000 });
  const restored = await page.$$eval(".msg", (els) => els.map((e) => e.className + "|" + e.textContent.slice(0, 40)));
  console.log("after login reload:", JSON.stringify(restored, null, 1));

  // Screenshot for the record
  await page.screenshot({ path: __dirname + "/portal.png", fullPage: true });

  // Migration
  page.on("dialog", (d) => d.accept());
  await page.click("#btn-migrate");
  await page.waitForSelector("#migrate-overlay:not(.hidden)", { timeout: 15000 });
  console.log("sovereign onion:", await page.textContent("#migrate-card .upa-box code"));
  console.log("mode chip:", await page.textContent("#mode-chip"));
  await page.screenshot({ path: __dirname + "/migrate.png" });

  await browser.close();
  console.log("E2E OK");
})().catch((err) => { console.error("E2E FAIL:", err); process.exit(1); });
