/* Two identities on one host complete the full peer flow: Alice mints an
 * invite, Bob accepts it (connect handshake), Bob writes to Alice, and Alice
 * receives and decrypts it over her per-relationship slot. */
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
    await page.goto(base + "/");
    await page.click("#btn-register");
    await page.waitForSelector("#welcome-overlay:not(.hidden)", { timeout: 20000 });
    await page.click("#welcome-continue");
    await page.waitForSelector("#mailbox-view:not(.hidden)");
    return page;
  }

  // Alice mints an invite for Bob
  const alice = await newIdentity("alice");
  await alice.click("#btn-create-invite");
  await alice.waitForSelector("#invite-overlay:not(.hidden)");
  await alice.fill("#invite-label", "Bob");
  await alice.click("#invite-mint");
  await alice.waitForSelector("#invite-result:not(.hidden)", { timeout: 15000 });
  const inviteUpa = (await alice.textContent("#invite-upa")).trim();
  await alice.click("#invite-close");
  console.log("invite minted:", inviteUpa.slice(0, 40) + "…");

  // Bob accepts the invite (connect handshake runs same-host)
  const bob = await newIdentity("bob");
  await bob.fill("#new-contact-name", "Alice");
  await bob.fill("#new-contact-upa", inviteUpa);
  await bob.click("#add-contact-form button[type=submit]");
  await bob.locator("#contact-list li", { hasText: "Alice" }).waitFor({ timeout: 15000 });
  console.log("bob connected to Alice");

  // Bob writes to Alice
  await bob.locator("#contact-list li", { hasText: "Alice" }).click();
  await bob.waitForSelector("#compose:not(.hidden)");
  await bob.fill("#compose-input", "hello from bob");
  await bob.click("#compose button");
  await bob.waitForSelector(".msg.out", { timeout: 15000 });

  // Alice's thread for Bob appears (via the connect handshake + WS notify);
  // open it and read the decrypted message.
  await alice.locator("#contact-list li", { hasText: "Bob" }).waitFor({ timeout: 15000 });
  await alice.locator("#contact-list li", { hasText: "Bob" }).click();
  await alice.waitForSelector(".msg.in", { timeout: 15000 });
  const received = (await alice.textContent(".msg.in")).trim();
  console.log("alice received:", received);
  if (!received.includes("hello from bob")) {
    throw new Error(`Alice did not receive Bob's message (got: ${received})`);
  }

  // And Alice replies back over the established session
  await alice.fill("#compose-input", "hi bob, got it");
  await alice.click("#compose button");
  await alice.waitForSelector(".msg.out", { timeout: 15000 });
  await bob.locator("#contact-list li", { hasText: "Alice" }).click();
  await bob.waitForFunction(
    () => [...document.querySelectorAll(".msg.in")].some(
      (e) => e.textContent.includes("hi bob, got it")),
    { timeout: 15000 },
  );
  console.log("bob received Alice's reply");

  await browser.close();
  console.log("PEER E2E OK");
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
