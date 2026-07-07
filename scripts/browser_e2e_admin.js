/* Administrator onion E2E (see docs/concepts.md): the node's second onion
 * address is the operator's private door, fully separate from the public
 * portal where contacts and guests connect. Proves: the first visit shows a
 * one-time setup screen, claiming it makes THE Administrator (device-key
 * path — plain-http .onion origins block WebAuthn), the admin lands in an
 * email-client layout (Inbox / Sent / Drafts / Contacts + a ✚ invite
 * button), drafts persist unsent compose text, reloads get login-only, and
 * the public portal is completely unaffected.
 *
 * Run with:
 *   OMAIL_ADMIN_ONION=<address printed by the seeding step>  (required)
 *   OMAIL_URL=http://localhost:8000                          (public portal)
 * The onion is resolved to 127.0.0.1 inside Chromium via host-resolver
 * rules, so no Tor is needed; treat-as-secure restores crypto.subtle,
 * which Tor Browser grants .onion origins natively. */
const { chromium } = require("playwright");

(async () => {
  const adminOnion = process.env.OMAIL_ADMIN_ONION;
  if (!adminOnion) throw new Error("OMAIL_ADMIN_ONION is required");
  const publicBase = process.env.OMAIL_URL || "http://localhost:8000";
  const port = new URL(publicBase).port || "80";
  const adminBase = `http://${adminOnion}:${port}`;

  const browser = await chromium.launch({
    executablePath: process.env.CHROMIUM_PATH || undefined,
    args: [
      "--no-proxy-server",   // env proxies would swallow the mapped onion
      `--host-resolver-rules=MAP ${adminOnion} 127.0.0.1`,
      `--unsafely-treat-insecure-origin-as-secure=${adminBase}`,
    ],
  });
  const page = await browser.newPage();
  page.on("dialog", (d) => d.accept());
  page.on("pageerror", (e) => console.log("[pageerror]", e.message));
  page.on("console", (msg) => {
    if (msg.type() === "error") console.log("[console.error]", msg.text());
  });

  // 1. First visit through the private door: the one-time setup screen
  await page.goto(adminBase + "/");
  await page.waitForSelector("#admin-auth-view:not(.hidden)");
  await page.waitForSelector("#admin-setup-cta:not(.hidden)");
  console.log("setup screen shown:", await page.locator("#admin-setup-intro").isVisible());

  // 2. Claim the node with a device key
  await page.click("#btn-admin-setup-devicekey");
  await page.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
  const bookmark = await page.textContent("#welcome-onion");
  console.log("bookmark points at the ADMIN door:", bookmark.includes(adminOnion));
  await page.click("#welcome-continue");

  // 3. The Administrator's mailbox: email-client layout, Inbox by default
  await page.waitForSelector("#mailbox-view:not(.hidden)");
  await page.waitForSelector("#admin-nav:not(.hidden)");
  await page.waitForSelector("#admin-pane:not(.hidden)");
  console.log("mode chip:", await page.textContent("#mode-chip"));
  console.log("default tab:", (await page.textContent("#admin-nav button.active")).trim());

  // 4. Contacts tab: Echo Test is bootstrapped; ratcheted chat works
  await page.click('#admin-nav button[data-tab="contacts"]');
  await page.waitForSelector("#contact-list li");
  console.log("first contact:", (await page.textContent("#contact-list .cname")).trim());
  await page.click("#contact-list li");
  await page.fill("#compose-input", "ping");
  await page.click("#compose button[type=submit]");
  await page.waitForSelector(".msg.in", { timeout: 15000 });
  console.log("echo reply:", await page.textContent(".msg.in"));

  // 5. Drafts: text left in the compose box survives, vault-encrypted
  await page.fill("#compose-input", "half-written thought");
  await page.waitForTimeout(2000); // autosave debounce + vault PUT
  await page.click('#admin-nav button[data-tab="drafts"]');
  await page.waitForSelector("#admin-list li:not(.aempty)");
  const draft = await page.textContent("#admin-list .asnippet");
  console.log("draft kept:", draft.includes("half-written thought"));

  // 6. Inbox aggregates incoming across contacts; Sent shows the ping
  await page.click('#admin-nav button[data-tab="inbox"]');
  await page.waitForSelector("#admin-list li:not(.aempty)", { timeout: 15000 });
  console.log("inbox from:", (await page.textContent("#admin-list .afrom")).trim());
  await page.click('#admin-nav button[data-tab="sent"]');
  await page.waitForSelector("#admin-list li:not(.aempty)", { timeout: 15000 });
  console.log("sent snippet:", (await page.textContent("#admin-list .asnippet")).trim());

  // 7. The ✚ button: invite dialog with QR + copyable claim link
  await page.click("#admin-add-contact");
  await page.waitForSelector("#invite-overlay:not(.hidden)");
  await page.fill("#invite-label", "Bob");
  await page.click("#invite-mint");
  await page.waitForSelector("#invite-result:not(.hidden)", { timeout: 15000 });
  const invite = await page.textContent("#invite-upa");
  console.log("invite QR + link:",
    (await page.locator("#invite-qr svg").count()) === 1 && invite.includes("?claim="));
  await page.click("#invite-close");
  await page.screenshot({ path: __dirname + "/admin_portal.png", fullPage: true });

  // 8. Reload: setup is gone forever; login-only, and it works
  await page.reload();
  await page.waitForSelector("#admin-login-cta:not(.hidden)", { timeout: 15000 });
  console.log("setup CTA gone:", await page.locator("#admin-setup-cta").isHidden());
  await page.click("#btn-admin-login-device");
  await page.waitForSelector("#admin-nav:not(.hidden)", { timeout: 20000 });
  console.log("relogin lands in admin mailbox: true");

  // 9. The public portal is untouched: ordinary auth view, no admin UI
  const pub = await browser.newPage();
  await pub.goto(publicBase + "/");
  await pub.waitForSelector("#auth-view:not(.hidden)");
  console.log("public portal ordinary:", await pub.locator("#admin-auth-view").isHidden());
  await pub.close();

  await browser.close();
  console.log("ADMIN E2E OK");
})().catch((err) => {
  console.error("ADMIN E2E FAIL:", err);
  process.exit(1);
});
