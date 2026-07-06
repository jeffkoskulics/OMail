/*
 * OMail portal client.
 *
 * Everything sensitive happens here, in the browser:
 *   - the Ed25519 identity is generated locally and never leaves as plaintext
 *   - the WebAuthn PRF secret (evaluated inside the authenticator) derives
 *     the vault key; the host stores only AES-GCM ciphertext
 *   - Triple Ratchet sessions run client-side; the host routes envelopes
 */
(function () {
  "use strict";
  const C = globalThis.OMailCrypto;
  const { qrcodegen } = globalThis.OMailVendor;
  const $ = (sel) => document.querySelector(sel);
  const te = new TextEncoder();
  const td = new TextDecoder();

  const HOST_NAME = document.body.dataset.hostName;
  const HOST_ONION = document.body.dataset.hostOnion;

  // ------------------------------------------------------------- state ----
  const state = {
    me: null,          // /api/me payload
    vaultKey: null,    // Uint8Array(32), PRF-derived
    vault: null,       // decrypted vault object
    contacts: [],
    activeContact: null,
    ratchets: {},      // upa -> TripleRatchet (live instances)
    unread: {},        // contact_id -> count
    ws: null,
  };

  // --------------------------------------------------------------- api ----
  async function api(path, options = {}) {
    const opts = { headers: {}, credentials: "same-origin", ...options };
    if (opts.json !== undefined) {
      opts.method = opts.method || "POST";
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.json);
      delete opts.json;
    }
    const resp = await fetch(path, opts);
    if (!resp.ok) {
      let detail = resp.statusText;
      try { detail = (await resp.json()).error || detail; } catch (e) { /* raw */ }
      const err = new Error(detail);
      err.status = resp.status;
      throw err;
    }
    return resp.json();
  }

  // ------------------------------------------------------------ webauthn --
  function decodeCreationOptions(options) {
    const pk = options.publicKey;
    pk.challenge = C.unb64url(pk.challenge);
    pk.user.id = C.unb64url(pk.user.id);
    (pk.excludeCredentials || []).forEach((c) => { c.id = C.unb64url(c.id); });
    pk.extensions = { ...(pk.extensions || {}), prf: {} };
    return options;
  }
  function decodeRequestOptions(options, credentialId) {
    const pk = options.publicKey;
    pk.challenge = C.unb64url(pk.challenge);
    (pk.allowCredentials || []).forEach((c) => { c.id = C.unb64url(c.id); });
    if (credentialId) {
      pk.allowCredentials = [{ type: "public-key", id: credentialId }];
    }
    pk.extensions = {
      ...(pk.extensions || {}),
      prf: { eval: { first: C.PRF_EVAL_INPUT } },
    };
    return options;
  }
  function encodeAttestation(credential) {
    return {
      id: credential.id,
      rawId: C.b64url(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        clientDataJSON: C.b64url(new Uint8Array(credential.response.clientDataJSON)),
        attestationObject: C.b64url(new Uint8Array(credential.response.attestationObject)),
      },
      clientExtensionResults: credential.getClientExtensionResults(),
    };
  }
  function encodeAssertion(credential) {
    const r = credential.response;
    return {
      id: credential.id,
      rawId: C.b64url(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        clientDataJSON: C.b64url(new Uint8Array(r.clientDataJSON)),
        authenticatorData: C.b64url(new Uint8Array(r.authenticatorData)),
        signature: C.b64url(new Uint8Array(r.signature)),
        userHandle: r.userHandle ? C.b64url(new Uint8Array(r.userHandle)) : null,
      },
      clientExtensionResults: {},
    };
  }
  function prfFromExtensions(credential) {
    const ext = credential.getClientExtensionResults();
    if (ext.prf && ext.prf.results && ext.prf.results.first) {
      return new Uint8Array(ext.prf.results.first);
    }
    return null;
  }

  // PRF unavailable (older authenticator/browser): degrade to a device-local
  // vault key so the mailbox still works. The banner makes the tradeoff loud.
  function fallbackVaultKey() {
    let stored = localStorage.getItem("omail-local-vault-key");
    if (!stored) {
      stored = C.b64(C.randomBytes(32));
      localStorage.setItem("omail-local-vault-key", stored);
    }
    setStatus("Authenticator lacks the PRF extension — vault key kept on this device instead of inside the passkey.", true);
    return C.unb64(stored);
  }

  async function obtainPrfViaAssertion(credentialId) {
    // A local, server-independent assertion purely to evaluate PRF inside
    // the authenticator (registration ceremonies don't return PRF output).
    try {
      const credential = await navigator.credentials.get({
        publicKey: {
          challenge: C.randomBytes(32),
          rpId: location.hostname,
          allowCredentials: [{ type: "public-key", id: credentialId }],
          userVerification: "preferred",
          extensions: { prf: { eval: { first: C.PRF_EVAL_INPUT } } },
        },
      });
      return prfFromExtensions(credential);
    } catch (err) {
      return null;
    }
  }

  // -------------------------------------------------------------- vault ----
  async function saveVault() {
    for (const [upa, ratchet] of Object.entries(state.ratchets)) {
      state.vault.ratchets[upa] = ratchet.toDict();
    }
    const blob = await C.vaultEncrypt(state.vaultKey, state.vault);
    await api("/api/vault", { method: "PUT", json: blob });
  }
  async function loadVault() {
    const blob = await api("/api/vault");
    state.vault = await C.vaultDecrypt(state.vaultKey, blob);
    state.ratchets = {};
    for (const [upa, dict] of Object.entries(state.vault.ratchets || {})) {
      state.ratchets[upa] = C.TripleRatchet.fromDict(dict);
    }
  }
  function newVault(identitySeed) {
    return {
      v: 1,
      identity_seed: C.b64(identitySeed),
      ratchets: {},
      responder_keys: {},
      relationships: {},   // rel_id -> { seed, inbound_upa, label, responder_keys }
    };
  }

  // Mint a per-relationship inbound slot: a fresh keypair (kept in the
  // vault) plus public prekey bundles the peer can initiate against. The
  // returned inbound_upa is the address to share out-of-band with this one
  // correspondent. See docs/concepts.md.
  async function createInvite(label, count = 3) {
    const seed = C.randomBytes(32);
    const slot = C.identityFromSeed(seed);
    const bundles = [];
    const privates = [];
    for (let i = 0; i < count; i++) {
      const { bundle, keys } = await C.makePrekeyBundle(seed);
      bundles.push(bundle);
      privates.push(keys);
    }
    const rel = await api("/api/relationships", {
      json: { label, slot_pub: C.b64(slot.edPub), bundles },
    });
    state.vault.relationships = state.vault.relationships || {};
    state.vault.relationships[rel.id] = {
      seed: C.b64(seed),
      inbound_upa: rel.inbound_upa,
      label,
      responder_keys: privates,
    };
    await saveVault();
    return rel;
  }

  async function publishPrekeys(count = 3) {
    const seed = C.unb64(state.vault.identity_seed);
    const bundles = [];
    const privates = [];
    for (let i = 0; i < count; i++) {
      const { bundle, keys } = await C.makePrekeyBundle(seed);
      bundles.push(bundle);
      privates.push(keys);
    }
    const result = await api("/api/prekeys", { json: { bundles } });
    result.prekey_ids.forEach((id, i) => {
      state.vault.responder_keys[id] = privates[i];
    });
    await saveVault();
  }

  // ----------------------------------------------------------- ratchets ----
  async function ratchetFor(contact) {
    const upa = contact.upa;
    if (state.ratchets[upa]) return { ratchet: state.ratchets[upa], prekeyId: null };
    const data = await api(`/api/bundle?upa=${encodeURIComponent(upa)}`);
    const seed = C.unb64(state.vault.identity_seed);
    const ratchet = await C.TripleRatchet.initiate(seed, data.bundle);
    state.ratchets[upa] = ratchet;
    return { ratchet, prekeyId: data.prekey_id };
  }

  async function openIncoming(contact, message) {
    // Returns plaintext string; establishes responder sessions on demand.
    const upa = contact.upa;
    const envelope = message.envelope;
    if (!state.ratchets[upa]) {
      if (!envelope.init) throw new Error("No session and no handshake blob");
      const keys = state.vault.responder_keys[envelope.prekey_id];
      if (!keys) throw new Error("Responder prekey not in vault");
      state.ratchets[upa] = await C.TripleRatchet.respond(keys, envelope.init);
      delete state.vault.responder_keys[envelope.prekey_id];
    }
    const plaintext = td.decode(await state.ratchets[upa].decrypt(envelope));
    // Replace the transit envelope with a vault-encrypted archive: the
    // host-side ciphertext (and the used message key) cease to exist.
    const archive = await C.vaultEncrypt(state.vaultKey, {
      text: plaintext, ts: message.created_at,
    });
    await api(`/api/messages/${message.id}/archive`, { json: archive });
    return plaintext;
  }

  // ----------------------------------------------------------------- ui ----
  function show(view) {
    $("#auth-view").classList.add("hidden");
    $("#mailbox-view").classList.add("hidden");
    $(view).classList.remove("hidden");
  }
  function setStatus(text, sticky = false) {
    const el = $("#auth-status");
    el.textContent = text || "";
    if (!sticky && text) setTimeout(() => { if (el.textContent === text) el.textContent = ""; }, 8000);
  }
  function renderQr(el, text) {
    const qr = qrcodegen(0, "M");
    qr.addData(text);
    qr.make();
    el.innerHTML = qr.createSvgTag({ cellSize: 4, margin: 2 });
  }
  function esc(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function renderSession() {
    const area = $("#session-area");
    if (state.me) {
      area.innerHTML = `<span>${esc(state.me.handle)}</span>
        <button id="btn-logout">Sign out</button>`;
      $("#btn-logout").addEventListener("click", logout);
    } else {
      area.innerHTML = "";
    }
    const chip = $("#mode-chip");
    const mode = state.me ? state.me.mode : "tenant";
    chip.textContent = mode;
    chip.classList.toggle("host", mode === "host");
  }

  function renderContacts() {
    const list = $("#contact-list");
    list.innerHTML = "";
    for (const contact of state.contacts) {
      const li = document.createElement("li");
      li.dataset.id = contact.id;
      if (state.activeContact && state.activeContact.id === contact.id) {
        li.classList.add("active");
      }
      const unread = state.unread[contact.id] || 0;
      li.innerHTML = `<span class="cname">${esc(contact.name)}</span>
        ${contact.is_host ? '<span class="chost">ADMIN</span>' : ""}
        ${unread ? `<span class="cbadge">${unread}</span>` : ""}`;
      li.addEventListener("click", () => openThread(contact));
      list.appendChild(li);
    }
  }

  function appendMessage(direction, text, ts) {
    const div = document.createElement("div");
    div.className = `msg ${direction}`;
    const when = ts ? new Date(ts * 1000).toLocaleString() : "";
    div.innerHTML = `${esc(text)}<span class="mtime">${when}</span>`;
    $("#messages").appendChild(div);
    $("#messages").scrollTop = $("#messages").scrollHeight;
  }
  function systemMessage(text) {
    const div = document.createElement("div");
    div.className = "msg system";
    div.textContent = text;
    $("#messages").appendChild(div);
  }

  async function openThread(contact) {
    state.activeContact = contact;
    state.unread[contact.id] = 0;
    renderContacts();
    $("#thread-title").textContent = contact.name;
    $("#thread-sub").textContent = contact.upa;
    $("#compose").classList.remove("hidden");
    $("#messages").innerHTML = "";
    systemMessage("Triple Ratchet session — end-to-end encrypted");

    let messages;
    try {
      messages = await api(`/api/messages?contact_id=${contact.id}`);
    } catch (err) {
      systemMessage(`Could not load messages: ${err.message}`);
      return;
    }
    let vaultDirty = false;
    for (const message of messages) {
      try {
        if (message.envelope && message.direction === "in") {
          const text = await openIncoming(contact, message);
          appendMessage("in", text, message.created_at);
          vaultDirty = true;
        } else if (message.archive) {
          const data = await C.vaultDecrypt(state.vaultKey, message.archive);
          appendMessage(message.direction, data.text, message.created_at);
        }
      } catch (err) {
        systemMessage(`⚠ message ${message.id}: ${err.message}`);
      }
    }
    if (vaultDirty) await saveVault();
  }

  async function sendCurrent(event) {
    event.preventDefault();
    const input = $("#compose-input");
    const text = input.value.trim();
    const contact = state.activeContact;
    if (!text || !contact) return;
    input.value = "";
    try {
      const { ratchet, prekeyId } = await ratchetFor(contact);
      const envelope = await ratchet.encrypt(te.encode(text));
      const archive = await C.vaultEncrypt(state.vaultKey, {
        text, ts: Date.now() / 1000,
      });
      const payload = { contact_id: contact.id, envelope, archive };
      if (prekeyId !== null) payload.prekey_id = prekeyId;
      const result = await api("/api/messages/send", { json: payload });
      await saveVault();
      appendMessage("out", text, Date.now() / 1000);
      if (result.delivery === "queued-remote") {
        systemMessage("Queued: recipient lives on a remote host (federation over Tor is on the roadmap).");
      }
    } catch (err) {
      systemMessage(`⚠ send failed: ${err.message}`);
    }
  }

  // ------------------------------------------------------------- events ----
  function connectWs() {
    if (state.ws) try { state.ws.close(); } catch (e) { /* stale */ }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/ws`);
    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      if (data.type !== "message") return;
      if (state.activeContact && data.contact_id === state.activeContact.id) {
        await openThread(state.activeContact);
      } else {
        state.unread[data.contact_id] = (state.unread[data.contact_id] || 0) + 1;
        await refreshContacts();
      }
    };
    ws.onclose = () => { setTimeout(connectWs, 3000); };
    state.ws = ws;
  }

  async function refreshContacts() {
    state.contacts = await api("/api/contacts");
    renderContacts();
  }

  // -------------------------------------------------------------- flows ----
  async function register() {
    try {
      setStatus("Waiting for your authenticator…", true);
      const begin = await api("/api/webauthn/register/begin", { json: {} });
      const credential = await navigator.credentials.create(
        decodeCreationOptions(begin.options),
      );
      // The identity key pair is born here, in the browser.
      const seed = C.randomBytes(32);
      const identity = C.identityFromSeed(seed);
      const info = await api("/api/webauthn/register/complete", {
        json: {
          ceremony: begin.ceremony,
          credential: encodeAttestation(credential),
          identity_pub: C.b64(identity.edPub),
        },
      });
      state.me = info;

      // PRF: evaluate inside the authenticator; fall back if unsupported.
      setStatus("Deriving your vault key inside the authenticator…", true);
      let prf = prfFromExtensions(credential);
      if (!prf) prf = await obtainPrfViaAssertion(new Uint8Array(credential.rawId));
      state.vaultKey = prf ? await C.deriveVaultKey(prf) : fallbackVaultKey();

      state.vault = newVault(seed);
      await saveVault();
      await publishPrekeys();
      setStatus("");
      await enterMailbox();
      showWelcome();
    } catch (err) {
      setStatus(`Registration failed: ${err.message}`, true);
      revealDeviceFallback();
    }
  }

  async function login() {
    try {
      setStatus("Waiting for your passkey…", true);
      const begin = await api("/api/webauthn/login/begin", { json: {} });
      const credential = await navigator.credentials.get(
        decodeRequestOptions(begin.options),
      );
      const info = await api("/api/webauthn/login/complete", {
        json: { ceremony: begin.ceremony, credential: encodeAssertion(credential) },
      });
      state.me = info;
      const prf = prfFromExtensions(credential);
      state.vaultKey = prf ? await C.deriveVaultKey(prf) : fallbackVaultKey();
      await loadVault();
      setStatus("");
      await enterMailbox();
    } catch (err) {
      setStatus(`Sign-in failed: ${err.message}`, true);
      revealDeviceFallback();
    }
  }

  // Device-key fallback: for browsers where WebAuthn is unavailable or
  // blocked (Tor Browser; Chromium on plain-http .onion origins). An
  // Ed25519 key generated and kept in this browser profile signs a server
  // challenge. Strictly weaker than a passkey — the UI says so.
  const DEVICE_KEY_STORAGE = "omail-device-key";

  const { nacl } = globalThis.OMailVendor;

  function deviceKeyPair(create) {
    let stored = localStorage.getItem(DEVICE_KEY_STORAGE);
    if (!stored) {
      if (!create) return null;
      stored = C.b64(C.randomBytes(32));
      localStorage.setItem(DEVICE_KEY_STORAGE, stored);
    }
    return nacl.sign.keyPair.fromSeed(C.unb64(stored));
  }

  function signChallenge(pair, challenge) {
    return C.b64(
      nacl.sign.detached(new TextEncoder().encode(challenge), pair.secretKey),
    );
  }

  async function deviceRegister() {
    const sure = confirm(
      "Create a DEVICE-KEY identity?\n\nNo passkey will protect this " +
      "account. A key stored in this browser profile becomes your only " +
      "way in — clearing site data or losing this device deletes the " +
      "identity permanently.",
    );
    if (!sure) return;
    try {
      setStatus("Creating your device-key identity…", true);
      const begin = await api("/api/devicekey/register/begin", { json: {} });
      const pair = deviceKeyPair(true);
      const idSeed = C.randomBytes(32);
      const identity = C.identityFromSeed(idSeed);
      const info = await api("/api/devicekey/register/complete", {
        json: {
          ceremony: begin.ceremony,
          device_pub: C.b64(pair.publicKey),
          signature: signChallenge(pair, begin.challenge),
          identity_pub: C.b64(identity.edPub),
        },
      });
      state.me = info;
      state.vaultKey = fallbackVaultKey();
      state.vault = newVault(idSeed);
      await saveVault();
      await publishPrekeys();
      setStatus("Signed in with a device key — this browser profile holds your only credentials.", true);
      await enterMailbox();
      showWelcome();
    } catch (err) {
      setStatus(`Device-key registration failed: ${err.message}`, true);
    }
  }

  async function deviceLogin() {
    try {
      const pair = deviceKeyPair(false);
      if (!pair) {
        setStatus("No device key in this browser — create an identity first.", true);
        return;
      }
      setStatus("Signing in with this browser's device key…", true);
      const begin = await api("/api/devicekey/login/begin", { json: {} });
      const info = await api("/api/devicekey/login/complete", {
        json: {
          ceremony: begin.ceremony,
          device_pub: C.b64(pair.publicKey),
          signature: signChallenge(pair, begin.challenge),
        },
      });
      state.me = info;
      state.vaultKey = fallbackVaultKey();
      await loadVault();
      setStatus("");
      await enterMailbox();
    } catch (err) {
      setStatus(`Device-key sign-in failed: ${err.message}`, true);
    }
  }

  function revealDeviceFallback() {
    $("#fallback-cta").classList.remove("hidden");
    $("#fallback-note").classList.remove("hidden");
  }

  async function logout() {
    try { await api("/api/logout", { json: {} }); } catch (e) { /* expired */ }
    location.reload();
  }

  async function enterMailbox() {
    renderSession();
    $("#me-handle").textContent = state.me.handle;
    $("#me-upa").textContent = state.me.upa;
    await refreshContacts();
    connectWs();
    show("#mailbox-view");
    const host = state.contacts.find((c) => c.is_host);
    if (host) openThread(host);
  }

  function showWelcome() {
    $("#welcome-handle").textContent = state.me.handle;
    $("#welcome-upa").textContent = state.me.upa;
    $("#welcome-onion").textContent = `http://${state.me.host_onion}`;
    renderQr($("#welcome-qr"), state.me.upa);
    $("#welcome-overlay").classList.remove("hidden");
  }

  async function migrate() {
    const sure = confirm(
      "Become your own host?\n\nThis generates an independent .onion service " +
      "for your identity and rewrites your UPA routing. Contacts will need " +
      "your new UPA.",
    );
    if (!sure) return;
    try {
      const result = await api("/api/migrate", { json: {} });
      state.me = await api("/api/me");
      renderSession();
      $("#me-upa").textContent = state.me.upa;
      const card = $("#migrate-card");
      card.innerHTML = `
        <h2>⚑ You are sovereign.</h2>
        <p>This node shifted from <strong>Tenant Mode</strong> to
           <strong>Host Mode</strong>. Routing tables were updated and
           confirmed on the host terminal.</p>
        <h3>Your independent onion service</h3>
        <p class="upa-box"><code>${esc(result.onion)}</code></p>
        <h3>Your new UPA</h3>
        <p class="upa-box"><code>${esc(result.upa)}</code></p>
        <p class="subtle">Tor descriptor: ${result.tor_active
          ? "published — reachable now"
          : "will publish on next node launch"}.
          Your old UPA (<code>${esc(result.old_upa)}</code>) no longer routes.</p>
        <div class="warn"><strong>Bookmark your new onion address</strong> —
          it is now the only door.</div>
        <button class="primary" id="migrate-close">Understood</button>`;
      $("#migrate-overlay").classList.remove("hidden");
      $("#migrate-close").addEventListener("click", () => {
        $("#migrate-overlay").classList.add("hidden");
      });
    } catch (err) {
      alert(`Migration failed: ${err.message}`);
    }
  }

  // --------------------------------------------------------------- boot ----
  function boot() {
    document.title = `${HOST_NAME} OMail`;
    $("#host-title").textContent = `${HOST_NAME} OMail`;
    $("#banner-onion").textContent = `http://${HOST_ONION}`;
    $("#footer-onion").textContent = HOST_ONION;

    if (!localStorage.getItem("omail-bookmark-ack")) {
      $("#bookmark-banner").classList.remove("hidden");
    }
    $("#bookmark-dismiss").addEventListener("click", () => {
      localStorage.setItem("omail-bookmark-ack", "1");
      $("#bookmark-banner").classList.add("hidden");
    });

    $("#btn-register").addEventListener("click", register);
    $("#btn-login").addEventListener("click", login);
    $("#btn-register-device").addEventListener("click", deviceRegister);
    $("#btn-login-device").addEventListener("click", deviceLogin);
    $("#compose").addEventListener("submit", sendCurrent);
    $("#btn-migrate").addEventListener("click", migrate);
    $("#welcome-continue").addEventListener("click", () => {
      $("#welcome-overlay").classList.add("hidden");
    });
    $("#btn-show-qr").addEventListener("click", () => {
      $("#qr-upa").textContent = state.me.upa;
      renderQr($("#qr-code"), state.me.upa);
      $("#qr-overlay").classList.remove("hidden");
    });
    $("#qr-close").addEventListener("click", () => {
      $("#qr-overlay").classList.add("hidden");
    });
    $("#btn-create-invite").addEventListener("click", () => {
      $("#invite-label").value = "";
      $("#invite-result").classList.add("hidden");
      $("#invite-mint").disabled = false;
      $("#invite-overlay").classList.remove("hidden");
    });
    $("#invite-close").addEventListener("click", () => {
      $("#invite-overlay").classList.add("hidden");
    });
    $("#invite-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const label = $("#invite-label").value.trim();
      if (!label) return;
      $("#invite-mint").disabled = true;
      try {
        const rel = await createInvite(label);
        $("#invite-upa").textContent = rel.inbound_upa;
        renderQr($("#invite-qr"), rel.inbound_upa);
        $("#invite-result").classList.remove("hidden");
      } catch (err) {
        alert(`Could not create invite: ${err.message}`);
        $("#invite-mint").disabled = false;
      }
    });
    document.querySelectorAll("button.copy").forEach((button) => {
      button.addEventListener("click", () => {
        navigator.clipboard.writeText($(button.dataset.copy).textContent);
        button.textContent = "✓";
        setTimeout(() => { button.textContent = "⧉"; }, 1200);
      });
    });
    $("#add-contact-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const name = $("#new-contact-name").value.trim();
      const upa = $("#new-contact-upa").value.trim();
      try {
        await api("/api/contacts", { json: { name, upa } });
        $("#new-contact-name").value = "";
        $("#new-contact-upa").value = "";
        await refreshContacts();
      } catch (err) {
        alert(`Could not add contact: ${err.message}`);
      }
    });

    if (!window.PublicKeyCredential) {
      setStatus("This browser lacks WebAuthn — you can continue with a device key instead.", true);
      $("#btn-register").disabled = true;
      $("#btn-login").disabled = true;
      revealDeviceFallback();
    } else if (localStorage.getItem(DEVICE_KEY_STORAGE)) {
      // A device key exists from a previous fallback session; keep the
      // door visible so its owner can sign back in.
      revealDeviceFallback();
    }
    show("#auth-view");
    renderSession();
  }

  boot();
})();
