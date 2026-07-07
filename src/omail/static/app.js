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
  // Which door did this page load through? The public onion serves contacts
  // and guests; the admin onion serves exactly one person — the operator.
  const IS_ADMIN_ONION = document.body.dataset.isAdminOnion === "true";
  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  // ------------------------------------------------------------- state ----
  const state = {
    me: null,          // /api/me payload
    vaultKey: null,    // Uint8Array(32), PRF-derived
    vault: null,       // decrypted vault object
    contacts: [],
    relByContact: {},  // contact_id -> relationship row
    activeContact: null,
    ratchets: {},      // upa -> TripleRatchet (live instances)
    unread: {},        // contact_id -> count
    adminTab: null,    // "inbox" | "sent" | "drafts" | "contacts" (admin only)
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
    state.vault.drafts = state.vault.drafts || {};
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
      drafts: {},          // contact upa -> { text, ts } — unsent compose text
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
    storeRelationshipSlot(rel, seed, privates);
    await saveVault();
    return rel;
  }

  // Accept an invite someone shared out-of-band: mint our own reverse slot
  // (kept in the vault), post it with the invite, and let the host run the
  // connect handshake. A thread for this correspondent is created server-side.
  async function acceptInvite(label, inviteUpa, count = 3) {
    const seed = C.randomBytes(32);
    const slot = C.identityFromSeed(seed);
    const bundles = [];
    const privates = [];
    for (let i = 0; i < count; i++) {
      const { bundle, keys } = await C.makePrekeyBundle(seed);
      bundles.push(bundle);
      privates.push(keys);
    }
    const rel = await api("/api/relationships/accept", {
      json: { invite_upa: inviteUpa, label, slot_pub: C.b64(slot.edPub), bundles },
    });
    storeRelationshipSlot(rel, seed, privates);
    await saveVault();
    return rel;
  }

  function claimUrlFor(inboundUpa) {
    const url = new URL(location.href);
    url.search = `?claim=${encodeURIComponent(inboundUpa)}`;
    url.hash = "";
    return url.toString();
  }

  // Invites are shared as one link either way (see createInvite); accept
  // either the bare address or the full ?claim= URL someone pastes here.
  function extractInviteUpa(text) {
    text = text.trim();
    try {
      const claim = new URL(text).searchParams.get("claim");
      if (claim) return claim.trim().toLowerCase();
    } catch (err) { /* not a URL: treat as a bare address */ }
    return text.toLowerCase();
  }

  // Store a minted slot's private material in the vault, keying each
  // responder key by the server prekey id (so an inbound handshake envelope
  // naming that prekey_id can be answered).
  function storeRelationshipSlot(rel, seed, privates) {
    state.vault.relationships = state.vault.relationships || {};
    const responderKeys = {};
    (rel.prekey_ids || []).forEach((id, i) => { responderKeys[id] = privates[i]; });
    state.vault.relationships[rel.id] = {
      seed: C.b64(seed),
      inbound_upa: rel.inbound_upa,
      label: rel.label,
      responder_keys: responderKeys,
    };
  }

  // Resolve the responder key for an inbound handshake prekey_id, scoped to
  // the contact's relationship. Identity prekeys (user_prekeys) and
  // relationship prekeys (relationship_prekeys) are separate id spaces that
  // both start at 1, so a peer message must look ONLY in its own slot, never
  // the flat identity map. Returns { keys, consume } or null.
  function responderKeyFor(contact, prekeyId) {
    const rel = state.relByContact[contact.id];
    if (rel && state.vault.relationships[rel.id]) {
      const rk = state.vault.relationships[rel.id].responder_keys || {};
      if (rk[prekeyId] !== undefined) {
        return { keys: rk[prekeyId], consume: () => { delete rk[prekeyId]; } };
      }
      return null;  // a peer slot never falls back to identity keys
    }
    if (state.vault.responder_keys[prekeyId] !== undefined) {
      return {
        keys: state.vault.responder_keys[prekeyId],
        consume: () => { delete state.vault.responder_keys[prekeyId]; },
      };
    }
    return null;
  }

  async function loadRelationships() {
    try {
      const rels = await api("/api/relationships");
      state.relByContact = {};
      for (const rel of rels) {
        if (rel.contact_id != null) state.relByContact[rel.contact_id] = rel;
      }
    } catch (err) {
      // relationships are optional context; ignore transient failures
    }
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
      const found = responderKeyFor(contact, envelope.prekey_id);
      if (!found) throw new Error("Responder prekey not in vault");
      state.ratchets[upa] = await C.TripleRatchet.respond(found.keys, envelope.init);
      found.consume();
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
    $("#admin-auth-view").classList.add("hidden");
    $("#mailbox-view").classList.add("hidden");
    $(view).classList.remove("hidden");
  }
  function setStatus(text, sticky = false, selector = "#auth-status") {
    const el = $(selector);
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
    const mode = state.me && state.me.is_admin
      ? "admin" : (state.me ? state.me.mode : "tenant");
    chip.textContent = mode;
    chip.classList.toggle("host", mode === "host" || mode === "admin");
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

  // Decrypt a contact's full thread to plaintext entries. Shared by the
  // per-contact thread view and the Administrator's aggregated Inbox/Sent
  // lists; incoming ciphertext is archived (vault-encrypted) as a side
  // effect, exactly as when the thread itself is opened.
  async function fetchThread(contact) {
    const messages = await api(`/api/messages?contact_id=${contact.id}`);
    const entries = [];
    let vaultDirty = false;
    for (const message of messages) {
      try {
        if (message.envelope && message.direction === "in") {
          const text = await openIncoming(contact, message);
          entries.push({ direction: "in", text, ts: message.created_at });
          vaultDirty = true;
        } else if (message.archive) {
          const data = await C.vaultDecrypt(state.vaultKey, message.archive);
          entries.push({
            direction: message.direction, text: data.text, ts: message.created_at,
          });
        }
      } catch (err) {
        console.error(`message ${message.id} failed`, err);
        entries.push({
          direction: "error",
          text: `⚠ message ${message.id}: ${err.message || err}`,
          ts: message.created_at,
        });
      }
    }
    if (vaultDirty) await saveVault();
    return entries;
  }

  async function openThread(contact) {
    const previous = state.activeContact;
    state.activeContact = contact;
    state.unread[contact.id] = 0;
    renderContacts();
    $("#thread-title").textContent = contact.name;
    $("#thread-sub").textContent = contact.upa;
    $("#compose").classList.remove("hidden");
    // Unsent compose text comes back where it was left — but never clobber
    // what's being typed right now (this rerenders on every live message).
    const input = $("#compose-input");
    if (!previous || previous.id !== contact.id || !input.value.trim()) {
      const draft = (state.vault.drafts || {})[contact.upa];
      input.value = draft ? draft.text : "";
    }
    $("#messages").innerHTML = "";
    systemMessage("Triple Ratchet session — end-to-end encrypted");

    let entries;
    try {
      entries = await fetchThread(contact);
    } catch (err) {
      systemMessage(`Could not load messages: ${err.message}`);
      return;
    }
    for (const entry of entries) {
      if (entry.direction === "error") systemMessage(entry.text);
      else appendMessage(entry.direction, entry.text, entry.ts);
    }
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
      delete (state.vault.drafts || {})[contact.upa];
      await saveVault();
      appendMessage("out", text, Date.now() / 1000);
      if (result.delivery === "queued-remote") {
        systemMessage("Queued: recipient lives on a remote host (federation over Tor is on the roadmap).");
      }
    } catch (err) {
      systemMessage(`⚠ send failed: ${err.message}`);
    }
  }

  // ------------------------------------------------------------- drafts ----
  // Compose text is auto-saved into the vault (encrypted like everything
  // else) as the user types, restored when the thread reopens, and cleared
  // on send. The Administrator's Drafts tab lists what's pending.
  let draftTimer = null;
  function scheduleDraftSave() {
    const contact = state.activeContact;
    if (!contact || !state.vault) return;
    clearTimeout(draftTimer);
    draftTimer = setTimeout(async () => {
      const text = $("#compose-input").value;
      state.vault.drafts = state.vault.drafts || {};
      const existing = state.vault.drafts[contact.upa];
      if (text.trim()) {
        if (existing && existing.text === text) return;
        state.vault.drafts[contact.upa] = { text, ts: Date.now() / 1000 };
      } else if (existing) {
        delete state.vault.drafts[contact.upa];
      } else {
        return;
      }
      try { await saveVault(); } catch (err) { /* next keystroke retries */ }
    }, 1200);
  }

  // ---------------------------------------------------------- admin nav ----
  // The Administrator gets an email-client layout: Inbox and Sent aggregate
  // every thread (decrypted client-side — the node can't build these lists),
  // Drafts shows unsent compose text, Contacts is the classic thread view.
  function adminNavButtons() {
    return document.querySelectorAll("#admin-nav button[data-tab]");
  }

  async function adminTab(tab) {
    state.adminTab = tab;
    adminNavButtons().forEach((button) => {
      button.classList.toggle("active", button.dataset.tab === tab);
    });
    const contactsMode = tab === "contacts";
    $("#sidebar").classList.toggle("hidden", !contactsMode);
    $("#thread").classList.toggle("hidden", !contactsMode);
    $("#admin-pane").classList.toggle("hidden", contactsMode);
    if (tab === "inbox") await renderAdminMailbox("in");
    else if (tab === "sent") await renderAdminMailbox("out");
    else if (tab === "drafts") renderAdminDrafts();
  }

  function adminRow({ title, snippet, time, onOpen }) {
    const li = document.createElement("li");
    li.innerHTML = `<span class="afrom">${esc(title)}</span>
      <span class="asnippet">${esc(snippet)}</span>
      <span class="atime">${esc(time)}</span>`;
    li.addEventListener("click", onOpen);
    return li;
  }

  function adminEmptyRow(text) {
    const li = document.createElement("li");
    li.className = "aempty";
    li.textContent = text;
    return li;
  }

  async function openFromAdminList(contact) {
    await adminTab("contacts");
    await openThread(contact);
  }

  async function renderAdminMailbox(direction) {
    const list = $("#admin-list");
    $("#admin-pane-title").textContent = direction === "in" ? "Inbox" : "Sent";
    $("#admin-pane-sub").textContent = "decrypting…";
    list.innerHTML = "";
    const rows = [];
    for (const contact of state.contacts) {
      let entries;
      try { entries = await fetchThread(contact); } catch (err) { continue; }
      for (const entry of entries) {
        if (entry.direction === direction) rows.push({ contact, ...entry });
      }
      if (direction === "in") state.unread[contact.id] = 0;
    }
    if (direction === "in") renderContacts();
    rows.sort((a, b) => (b.ts || 0) - (a.ts || 0));
    $("#admin-pane-sub").textContent =
      `${rows.length} message${rows.length === 1 ? "" : "s"} · decrypted in this browser`;
    if (!rows.length) {
      list.appendChild(adminEmptyRow(direction === "in"
        ? "Nothing yet. Add a contact (✚) and share the invite to start a conversation."
        : "No sent messages yet."));
      return;
    }
    for (const row of rows) {
      list.appendChild(adminRow({
        title: row.contact.name,
        snippet: row.text,
        time: row.ts ? new Date(row.ts * 1000).toLocaleString() : "",
        onOpen: () => openFromAdminList(row.contact),
      }));
    }
  }

  function renderAdminDrafts() {
    const list = $("#admin-list");
    $("#admin-pane-title").textContent = "Drafts";
    list.innerHTML = "";
    const drafts = Object.entries(state.vault.drafts || {})
      .sort((a, b) => (b[1].ts || 0) - (a[1].ts || 0));
    $("#admin-pane-sub").textContent =
      drafts.length ? `${drafts.length} unsent` : "";
    if (!drafts.length) {
      list.appendChild(adminEmptyRow(
        "No drafts. Text left unsent in a compose box is kept here automatically."));
      return;
    }
    for (const [upa, draft] of drafts) {
      const contact = state.contacts.find((c) => c.upa === upa);
      list.appendChild(adminRow({
        title: contact ? contact.name : upa,
        snippet: draft.text,
        time: draft.ts ? new Date(draft.ts * 1000).toLocaleString() : "",
        onOpen: () => { if (contact) openFromAdminList(contact); },
      }));
    }
  }

  // ------------------------------------------------------------- events ----
  function connectWs() {
    if (state.ws) try { state.ws.close(); } catch (e) { /* stale */ }
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/api/ws`);
    ws.onmessage = async (event) => {
      const data = JSON.parse(event.data);
      if (data.type === "contact") {
        // Someone connected to (or claimed) one of our invites: they now
        // appear without any action on our side (see docs/concepts.md).
        await refreshContacts();
        return;
      }
      if (data.type !== "message") return;
      if (state.adminTab === "inbox") {
        // The aggregated Inbox is on screen: fold the new message in live.
        await renderAdminMailbox("in");
      } else if (state.activeContact && data.contact_id === state.activeContact.id
                 && (!state.me.is_admin || state.adminTab === "contacts")) {
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
    await loadRelationships();
    renderContacts();
  }

  // -------------------------------------------------------------- flows ----
  // The admin setup screen reuses these flows with a different *begin*
  // endpoint (the gated /api/admin/setup/... ones) and status line; the
  // complete endpoints are shared — the ceremony itself carries the role.
  async function register(opts = {}) {
    const statusSel = opts.statusSel || "#auth-status";
    const onFallback = opts.onFallback || revealDeviceFallback;
    try {
      setStatus("Waiting for your authenticator…", true, statusSel);
      const begin = await api(
        opts.begin || "/api/webauthn/register/begin", { json: {} },
      );
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
      setStatus("Deriving your vault key inside the authenticator…", true, statusSel);
      let prf = prfFromExtensions(credential);
      if (!prf) prf = await obtainPrfViaAssertion(new Uint8Array(credential.rawId));
      state.vaultKey = prf ? await C.deriveVaultKey(prf) : fallbackVaultKey();

      state.vault = newVault(seed);
      await saveVault();
      await publishPrekeys();
      setStatus("", false, statusSel);
      await enterMailbox();
      showWelcome();
    } catch (err) {
      setStatus(`Registration failed: ${err.message}`, true, statusSel);
      onFallback();
    }
  }

  async function login(opts = {}) {
    const statusSel = opts.statusSel || "#auth-status";
    const onFallback = opts.onFallback || revealDeviceFallback;
    try {
      setStatus("Waiting for your passkey…", true, statusSel);
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
      setStatus("", false, statusSel);
      await enterMailbox();
    } catch (err) {
      setStatus(`Sign-in failed: ${err.message}`, true, statusSel);
      onFallback();
    }
  }

  // Guest claim: the invite UPA is a one-time claim capability (see
  // docs/concepts.md). Whoever opens the ?claim= link first completes the
  // ONE credential ceremony that becomes their permanent sign-in — after
  // that, only the credential grants access, not the link.
  function claimUpaFromUrl() {
    return new URLSearchParams(location.search).get("claim");
  }

  function clearClaimFromUrl() {
    const url = new URL(location.href);
    url.searchParams.delete("claim");
    history.replaceState(null, "", url.pathname + url.search);
  }

  async function claimGuestPasskey() {
    const inboundUpa = claimUpaFromUrl();
    try {
      setStatus("Waiting for your authenticator…", true, "#claim-status");
      const begin = await api("/api/guests/claim/webauthn/begin", {
        json: { inbound_upa: inboundUpa },
      });
      const credential = await navigator.credentials.create(
        decodeCreationOptions(begin.options),
      );
      const seed = C.randomBytes(32);
      const identity = C.identityFromSeed(seed);
      const info = await api("/api/guests/claim/webauthn/complete", {
        json: {
          ceremony: begin.ceremony,
          credential: encodeAttestation(credential),
          identity_pub: C.b64(identity.edPub),
        },
      });
      state.me = info;
      let prf = prfFromExtensions(credential);
      if (!prf) prf = await obtainPrfViaAssertion(new Uint8Array(credential.rawId));
      state.vaultKey = prf ? await C.deriveVaultKey(prf) : fallbackVaultKey();
      state.vault = newVault(seed);
      await saveVault();
      await publishPrekeys();
      clearClaimFromUrl();
      setStatus("");
      await enterMailbox();
      showWelcome();
    } catch (err) {
      setStatus(`Setup failed: ${err.message}`, true, "#claim-status");
    }
  }

  async function claimGuestDeviceKey() {
    const inboundUpa = claimUpaFromUrl();
    try {
      setStatus("Setting up your device key…", true, "#claim-status");
      const begin = await api("/api/guests/claim/devicekey/begin", {
        json: { inbound_upa: inboundUpa },
      });
      const pair = deviceKeyPair(true);
      const seed = C.randomBytes(32);
      const identity = C.identityFromSeed(seed);
      const info = await api("/api/guests/claim/devicekey/complete", {
        json: {
          ceremony: begin.ceremony,
          device_pub: C.b64(pair.publicKey),
          signature: signChallenge(pair, begin.challenge),
          identity_pub: C.b64(identity.edPub),
        },
      });
      state.me = info;
      state.vaultKey = fallbackVaultKey();
      state.vault = newVault(seed);
      await saveVault();
      await publishPrekeys();
      clearClaimFromUrl();
      setStatus("Set up with a device key — this browser profile holds your only credentials.", true, "#claim-status");
      await enterMailbox();
      showWelcome();
    } catch (err) {
      setStatus(`Setup failed: ${err.message}`, true, "#claim-status");
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

  async function deviceRegister(opts = {}) {
    const statusSel = opts.statusSel || "#auth-status";
    const sure = confirm(
      "Create a DEVICE-KEY identity?\n\nNo passkey will protect this " +
      "account. A key stored in this browser profile becomes your only " +
      "way in — clearing site data or losing this device deletes the " +
      "identity permanently.",
    );
    if (!sure) return;
    try {
      setStatus("Creating your device-key identity…", true, statusSel);
      const begin = await api(
        opts.begin || "/api/devicekey/register/begin", { json: {} },
      );
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
      setStatus("Signed in with a device key — this browser profile holds your only credentials.", true, statusSel);
      await enterMailbox();
      showWelcome();
    } catch (err) {
      setStatus(`Device-key registration failed: ${err.message}`, true, statusSel);
    }
  }

  async function deviceLogin(opts = {}) {
    const statusSel = opts.statusSel || "#auth-status";
    try {
      const pair = deviceKeyPair(false);
      if (!pair) {
        setStatus("No device key in this browser — create an identity first.", true, statusSel);
        return;
      }
      setStatus("Signing in with this browser's device key…", true, statusSel);
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
      setStatus("", false, statusSel);
      await enterMailbox();
    } catch (err) {
      setStatus(`Device-key sign-in failed: ${err.message}`, true, statusSel);
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
    if (state.me.is_admin) {
      $("#admin-nav").classList.remove("hidden");
      await adminTab("inbox");
      return;
    }
    const host = state.contacts.find((c) => c.is_host);
    if (host) openThread(host);
  }

  function showWelcome() {
    $("#welcome-handle").textContent = state.me.handle;
    $("#welcome-upa").textContent = state.me.upa;
    // The address worth bookmarking is the door actually in use: the admin
    // onion for the Administrator, the public portal for everyone else.
    $("#welcome-onion").textContent =
      IS_ADMIN_ONION ? `http://${location.host}` : `http://${state.me.host_onion}`;
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

  // ------------------------------------------------------- multi-device ----
  // Copying an identity to a new device is a deliberate action proving
  // ownership via the CURRENT session, not a bearer secret: this device
  // mints a short-lived link and uploads a parcel of the decrypted vault
  // encrypted with a link_secret that travels only inside the QR/URL
  // fragment (never sent to the server). The new device decrypts it
  // locally, then registers its own credential bound to the link.
  async function renderDevicesList() {
    const creds = await api("/api/credentials");
    const list = $("#devices-list");
    list.innerHTML = creds.map((c) => `<li>${esc(c.kind)} — added ${
      new Date(c.created_at * 1000).toLocaleString()}</li>`).join("");
  }

  async function startDeviceLink() {
    const { link_id } = await api("/api/devices/link/begin", { json: {} });
    const linkSecret = C.randomBytes(32);
    const parcel = await C.vaultEncrypt(linkSecret, {
      vault: state.vault, handle: state.me.handle,
    });
    await api("/api/devices/link/deliver", { json: { link_id, parcel } });
    const url = new URL(location.href);
    url.search = "";
    url.hash = `link=${link_id}.${C.b64(linkSecret)}`;
    $("#link-url").textContent = url.toString();
    renderQr($("#link-qr"), url.toString());
    $("#link-result").classList.remove("hidden");
  }

  function linkFragmentInfo() {
    const match = /^#?link=([^.]+)\.(.+)$/.exec(location.hash);
    if (!match) return null;
    return { linkId: match[1], secret: C.unb64(decodeURIComponent(match[2])) };
  }

  function clearLinkFromUrl() {
    history.replaceState(null, "", location.pathname + location.search);
  }

  async function completeLinkClaim(kind) {
    const linkInfo = linkFragmentInfo();
    if (!linkInfo) return;
    try {
      setStatus("Fetching your keys from the other device…", true, "#link-claim-status");
      let fetched = null;
      for (let i = 0; i < 10; i++) {
        fetched = await api(`/api/devices/link/fetch?link_id=${encodeURIComponent(linkInfo.linkId)}`);
        if (fetched.ready) break;
        await sleep(1000);
      }
      if (!fetched || !fetched.ready) {
        throw new Error("The other device hasn't delivered your keys yet — try again");
      }
      const parcel = await C.vaultDecrypt(linkInfo.secret, fetched.parcel);

      let result;
      if (kind === "passkey") {
        setStatus("Waiting for your authenticator…", true, "#link-claim-status");
        const begin = await api("/api/devices/link/claim/webauthn/begin", {
          json: { link_id: linkInfo.linkId },
        });
        const credential = await navigator.credentials.create(
          decodeCreationOptions(begin.options),
        );
        result = await api("/api/devices/link/claim/webauthn/complete", {
          json: { ceremony: begin.ceremony, credential: encodeAttestation(credential) },
        });
        let prf = prfFromExtensions(credential);
        if (!prf) prf = await obtainPrfViaAssertion(new Uint8Array(credential.rawId));
        state.vaultKey = prf ? await C.deriveVaultKey(prf) : fallbackVaultKey();
      } else {
        setStatus("Setting up your device key…", true, "#link-claim-status");
        const begin = await api("/api/devices/link/claim/devicekey/begin", {
          json: { link_id: linkInfo.linkId },
        });
        const pair = deviceKeyPair(true);
        result = await api("/api/devices/link/claim/devicekey/complete", {
          json: {
            ceremony: begin.ceremony, device_pub: C.b64(pair.publicKey),
            signature: signChallenge(pair, begin.challenge),
          },
        });
        state.vaultKey = fallbackVaultKey();
      }

      state.me = result;
      state.vault = parcel.vault;
      await saveVault();
      clearLinkFromUrl();
      setStatus("");
      await enterMailbox();
    } catch (err) {
      setStatus(`Linking failed: ${err.message}`, true, "#link-claim-status");
    }
  }

  // --------------------------------------------------------------- boot ----
  // First load on the admin onion: decide between the one-time setup screen
  // and the login-only screen. Both CTAs stay hidden until the node answers.
  async function adminBoot() {
    show("#admin-auth-view");
    renderSession();
    if (!window.PublicKeyCredential) {
      $("#btn-admin-setup-passkey").disabled = true;
      $("#btn-admin-login").disabled = true;
    }
    try {
      const status = await api("/api/admin/status");
      if (status.admin_exists) {
        $("#admin-setup-intro").classList.add("hidden");
        $("#admin-login-intro").classList.remove("hidden");
        $("#admin-login-cta").classList.remove("hidden");
      } else {
        $("#admin-setup-cta").classList.remove("hidden");
      }
    } catch (err) {
      setStatus(`Could not reach the node: ${err.message}`,
                true, "#admin-auth-status");
    }
  }

  function boot() {
    document.title = `${HOST_NAME} OMail`;
    $("#host-title").textContent = `${HOST_NAME} OMail`;
    // On the admin onion, THIS address (not the public one) is the bookmark
    // that matters — losing it means losing the admin door.
    $("#banner-onion").textContent =
      IS_ADMIN_ONION ? `http://${location.host}` : `http://${HOST_ONION}`;
    $("#footer-onion").textContent = HOST_ONION;

    if (!localStorage.getItem("omail-bookmark-ack")) {
      $("#bookmark-banner").classList.remove("hidden");
    }
    $("#bookmark-dismiss").addEventListener("click", () => {
      localStorage.setItem("omail-bookmark-ack", "1");
      $("#bookmark-banner").classList.add("hidden");
    });

    $("#btn-register").addEventListener("click", () => register());
    $("#btn-login").addEventListener("click", () => login());
    $("#btn-register-device").addEventListener("click", () => deviceRegister());
    $("#btn-login-device").addEventListener("click", () => deviceLogin());
    $("#btn-admin-setup-passkey").addEventListener("click", () => register({
      begin: "/api/admin/setup/webauthn/begin",
      statusSel: "#admin-auth-status",
      onFallback: () => {},   // device-key option is already on screen
    }));
    $("#btn-admin-setup-devicekey").addEventListener("click", () => deviceRegister({
      begin: "/api/admin/setup/devicekey/begin",
      statusSel: "#admin-auth-status",
    }));
    $("#btn-admin-login").addEventListener("click", () => login({
      statusSel: "#admin-auth-status", onFallback: () => {},
    }));
    $("#btn-admin-login-device").addEventListener("click", () => deviceLogin({
      statusSel: "#admin-auth-status",
    }));
    adminNavButtons().forEach((button) => {
      button.addEventListener("click", () => adminTab(button.dataset.tab));
    });
    $("#admin-add-contact").addEventListener("click", async () => {
      // The ✚ button: jump to Contacts and open the invite dialog — the QR
      // code / copyable link that encodes the UPA to hand to the contact.
      await adminTab("contacts");
      $("#btn-create-invite").click();
    });
    $("#compose").addEventListener("submit", sendCurrent);
    $("#compose-input").addEventListener("input", scheduleDraftSave);
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
        const url = claimUrlFor(rel.inbound_upa);
        $("#invite-upa").textContent = url;
        renderQr($("#invite-qr"), url);
        $("#invite-result").classList.remove("hidden");
      } catch (err) {
        alert(`Could not create invite: ${err.message}`);
        $("#invite-mint").disabled = false;
      }
    });
    $("#btn-devices").addEventListener("click", async () => {
      $("#link-result").classList.add("hidden");
      $("#devices-overlay").classList.remove("hidden");
      try { await renderDevicesList(); } catch (err) { /* transient */ }
    });
    $("#devices-close").addEventListener("click", () => {
      $("#devices-overlay").classList.add("hidden");
    });
    $("#btn-link-device").addEventListener("click", async () => {
      try {
        await startDeviceLink();
      } catch (err) {
        alert(`Could not start device linking: ${err.message}`);
      }
    });
    $("#btn-claim-passkey").addEventListener("click", claimGuestPasskey);
    $("#btn-claim-devicekey").addEventListener("click", claimGuestDeviceKey);
    $("#btn-linkclaim-passkey").addEventListener("click", () => completeLinkClaim("passkey"));
    $("#btn-linkclaim-devicekey").addEventListener("click", () => completeLinkClaim("devicekey"));

    document.querySelectorAll("button.copy").forEach((button) => {
      button.addEventListener("click", () => {
        navigator.clipboard.writeText($(button.dataset.copy).textContent);
        button.textContent = "✓";
        setTimeout(() => { button.textContent = "⧉"; }, 1200);
      });
    });
    $("#add-contact-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const name = $("#new-contact-name").value.trim() || "Contact";
      const raw = $("#new-contact-upa").value.trim();
      if (!raw) return;
      const upa = extractInviteUpa(raw);
      const submit = event.target.querySelector("button[type=submit]");
      submit.disabled = true;
      try {
        // Pasting an invite triggers the connect handshake with the sender's
        // host and establishes the two-way relationship.
        await acceptInvite(name, upa);
        $("#new-contact-name").value = "";
        $("#new-contact-upa").value = "";
        await refreshContacts();
      } catch (err) {
        alert(`Could not accept invite: ${err.message}`);
      } finally {
        submit.disabled = false;
      }
    });

    if (IS_ADMIN_ONION) {
      // The private door: setup on first visit, login-only forever after.
      // Invite/link claims never route here — those URLs carry the public
      // onion, so the ordinary branches below simply don't apply.
      adminBoot();
      return;
    }

    const claimUpa = claimUpaFromUrl();
    const linkInfo = linkFragmentInfo();
    if (linkInfo) {
      // Adding a device: this browser has no identity yet, only a link.
      show("#link-claim-view");
      if (!window.PublicKeyCredential) $("#btn-linkclaim-passkey").disabled = true;
      renderSession();
      return;
    }
    if (claimUpa) {
      // A guest invite link: the one-time claim ceremony.
      show("#claim-view");
      if (!window.PublicKeyCredential) $("#btn-claim-passkey").disabled = true;
      renderSession();
      return;
    }

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
