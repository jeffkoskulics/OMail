/*
 * OMail client-side cryptographic engine.
 *
 * A byte-for-byte wire-compatible mirror of omail/crypto/triple_ratchet.py:
 * PQXDH-style hybrid handshake, DH ratchet (X25519), symmetric HMAC chains,
 * and a KEM ratchet (ML-KEM-768, with a classical X25519-KEM mode).
 *
 * Primitives come from WebCrypto (HKDF, HMAC, AES-256-GCM, SHA-256) and the
 * vendored bundle (tweetnacl for X25519/Ed25519, ed2curve for birational key
 * conversion, noble post-quantum for ML-KEM-768). All private material lives
 * in memory or inside the PRF-encrypted vault — never in plaintext on the host.
 *
 * Runs in browsers and in Node (the JS<->Python interop tests).
 */
(function () {
  "use strict";
  const { nacl, ed2curve, ml_kem768 } = globalThis.OMailVendor;
  const subtle = globalThis.crypto.subtle;

  const MAX_SKIP = 512;
  const ROOT_INFO = "omail-ratchet-root";
  const X3DH_INFO = "omail-x3dh";
  const MSG_INFO = "omail-msg";

  // ---------------------------------------------------------------- bytes --
  const te = new TextEncoder();
  const td = new TextDecoder();

  function b64(u8) {
    let s = "";
    for (const b of u8) s += String.fromCharCode(b);
    return btoa(s);
  }
  function unb64(str) {
    const s = atob(str);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out;
  }
  function b64url(u8) {
    return b64(u8).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function unb64url(str) {
    const pad = "=".repeat((4 - (str.length % 4)) % 4);
    return unb64(str.replace(/-/g, "+").replace(/_/g, "/") + pad);
  }
  function concat(...arrays) {
    const total = arrays.reduce((n, a) => n + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) { out.set(a, offset); offset += a.length; }
    return out;
  }
  function randomBytes(n) {
    const out = new Uint8Array(n);
    globalThis.crypto.getRandomValues(out);
    return out;
  }

  // ----------------------------------------------------------------- kdfs --
  async function hkdf(ikm, salt, info, length) {
    const key = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
    const bits = await subtle.deriveBits(
      { name: "HKDF", hash: "SHA-256", salt, info: te.encode(info) },
      key, length * 8,
    );
    return new Uint8Array(bits);
  }
  async function hmac(keyBytes, data) {
    const key = await subtle.importKey(
      "raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
    );
    return new Uint8Array(await subtle.sign("HMAC", key, data));
  }
  async function sha256(data) {
    return new Uint8Array(await subtle.digest("SHA-256", data));
  }

  async function kdfRoot(rootKey, dhOut, kemSs) {
    const okm = await hkdf(concat(dhOut, kemSs), rootKey, ROOT_INFO, 64);
    return [okm.slice(0, 32), okm.slice(32)];
  }
  async function kdfChain(chainKey) {
    return [await hmac(chainKey, new Uint8Array([2])),
            await hmac(chainKey, new Uint8Array([1]))];
  }

  // ------------------------------------------------------------- payloads --
  function canonicalHeader(header) {
    // Matches Python json.dumps(header, sort_keys=True, separators=(",", ":"))
    const ordered = {};
    for (const key of Object.keys(header).sort()) ordered[key] = header[key];
    return te.encode(JSON.stringify(ordered));
  }
  async function msgEncrypt(messageKey, plaintext, ad) {
    const okm = await hkdf(messageKey, new Uint8Array(0), MSG_INFO, 44);
    const key = await subtle.importKey("raw", okm.slice(0, 32), "AES-GCM", false, ["encrypt"]);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv: okm.slice(32, 44), additionalData: ad }, key, plaintext,
    );
    return new Uint8Array(ct);
  }
  async function msgDecrypt(messageKey, ciphertext, ad) {
    const okm = await hkdf(messageKey, new Uint8Array(0), MSG_INFO, 44);
    const key = await subtle.importKey("raw", okm.slice(0, 32), "AES-GCM", false, ["decrypt"]);
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: okm.slice(32, 44), additionalData: ad }, key, ciphertext,
    );
    return new Uint8Array(pt);
  }

  // ---------------------------------------------------------------- x25519 --
  function genX25519() {
    const priv = randomBytes(32);
    return [priv, nacl.scalarMult.base(priv)];
  }
  function dh(priv, pub) {
    return nacl.scalarMult(priv, pub);
  }

  // ------------------------------------------------------------------ KEMs --
  const KEMS = {
    "ML-KEM-768": {
      generate() {
        const { publicKey, secretKey } = ml_kem768.keygen();
        return [publicKey, secretKey];
      },
      encaps(pub) {
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(pub);
        return [cipherText, sharedSecret];
      },
      decaps(priv, ct) {
        return Promise.resolve(ml_kem768.decapsulate(ct, priv));
      },
    },
    "X25519": {
      generate() {
        const [priv, pub] = genX25519();
        return [pub, priv];
      },
      encaps(pub) {
        const [ephPriv, ephPub] = genX25519();
        return sha256(concat(dh(ephPriv, pub), ephPub, pub))
          .then((ss) => [ephPub, ss]);
      },
      decaps(priv, ct) {
        const pub = nacl.scalarMult.base(priv);
        return sha256(concat(dh(priv, ct), ct, pub));
      },
    },
  };
  async function kemGenerate(alg) { return KEMS[alg].generate(); }
  async function kemEncaps(alg, pub) { return KEMS[alg].encaps(pub); }
  async function kemDecaps(alg, priv, ct) { return KEMS[alg].decaps(priv, ct); }

  // ----------------------------------------------------------- identities --
  function identityFromSeed(seed) {
    const pair = nacl.sign.keyPair.fromSeed(seed);
    return {
      seed,
      edPub: pair.publicKey,
      edSecret: pair.secretKey, // 64 bytes: seed || pub
      xPriv: ed2curve.convertSecretKey(pair.secretKey),
      xPub: ed2curve.convertPublicKey(pair.publicKey),
    };
  }

  async function makePrekeyBundle(seed, kemAlg = "ML-KEM-768") {
    const id = identityFromSeed(seed);
    const [spkPriv, spkPub] = genX25519();
    const [kemPub, kemPriv] = await kemGenerate(kemAlg);
    const bundle = {
      ik_ed: b64(id.edPub),
      ik_x: b64(id.xPub),
      spk: b64(spkPub),
      spk_sig: b64(nacl.sign.detached(spkPub, id.edSecret)),
      kem_pub: b64(kemPub),
      kem_alg: kemAlg,
    };
    const keys = {
      ik_ed_priv: b64(seed),
      spk_priv: b64(spkPriv),
      kem_priv: b64(kemPriv),
      kem_alg: kemAlg,
    };
    return { bundle, keys };
  }

  // -------------------------------------------------------- triple ratchet --
  class TripleRatchet {
    constructor() {
      this.kemAlg = "ML-KEM-768";
      this.rootKey = null;
      this.dhPriv = null;
      this.dhPub = null;
      this.remoteDhPub = null;
      this.kemPriv = null;
      this.kemPub = null;
      this.prevKemPriv = null;
      this.remoteKemPub = null;
      this.sendKemCt = null;
      this.ckSend = null;
      this.ckRecv = null;
      this.nSend = 0;
      this.nRecv = 0;
      this.pn = 0;
      this.skipped = new Map(); // "dhB64|n" -> message key
      this.handshake = null;
    }

    static async initiate(seed, bundle) {
      const ikEd = unb64(bundle.ik_ed);
      const spk = unb64(bundle.spk);
      if (!nacl.sign.detached.verify(spk, unb64(bundle.spk_sig), ikEd)) {
        throw new Error("Prekey bundle signature invalid");
      }
      const id = identityFromSeed(seed);
      const [ekPriv, ekPub] = genX25519();
      const dh1 = dh(id.xPriv, spk);
      const dh2 = dh(ekPriv, unb64(bundle.ik_x));
      const dh3 = dh(ekPriv, spk);
      const [kemCt0, kemSs0] = await kemEncaps(bundle.kem_alg, unb64(bundle.kem_pub));
      const sk = await hkdf(
        concat(dh1, dh2, dh3, kemSs0), new Uint8Array(32), X3DH_INFO, 32,
      );
      const state = new TripleRatchet();
      state.kemAlg = bundle.kem_alg;
      state.rootKey = sk;
      state.remoteDhPub = spk;
      state.remoteKemPub = unb64(bundle.kem_pub);
      state.handshake = {
        ik: b64(id.edPub),
        ik_x: b64(id.xPub),
        ek: b64(ekPub),
        kem_ct0: b64(kemCt0),
        kem_alg: bundle.kem_alg,
      };
      return state;
    }

    static async respond(keys, handshake) {
      if (handshake.kem_alg !== keys.kem_alg) {
        throw new Error("Handshake KEM algorithm mismatch");
      }
      const id = identityFromSeed(unb64(keys.ik_ed_priv));
      const spkPriv = unb64(keys.spk_priv);
      const dh1 = dh(spkPriv, unb64(handshake.ik_x));
      const dh2 = dh(id.xPriv, unb64(handshake.ek));
      const dh3 = dh(spkPriv, unb64(handshake.ek));
      const kemSs0 = await kemDecaps(
        keys.kem_alg, unb64(keys.kem_priv), unb64(handshake.kem_ct0),
      );
      const sk = await hkdf(
        concat(dh1, dh2, dh3, kemSs0), new Uint8Array(32), X3DH_INFO, 32,
      );
      const state = new TripleRatchet();
      state.kemAlg = keys.kem_alg;
      state.rootKey = sk;
      state.dhPriv = spkPriv;
      state.dhPub = nacl.scalarMult.base(spkPriv);
      state.kemPriv = unb64(keys.kem_priv);
      state.kemPub = new Uint8Array(0);
      return state;
    }

    async _ratchetSendStep() {
      [this.dhPriv, this.dhPub] = genX25519();
      const dhOut = dh(this.dhPriv, this.remoteDhPub);
      const [kemCt, kemSs] = await kemEncaps(this.kemAlg, this.remoteKemPub);
      this.sendKemCt = kemCt;
      const [newKemPub, newKemPriv] = await kemGenerate(this.kemAlg);
      this.prevKemPriv = this.kemPriv;
      this.kemPriv = newKemPriv;
      this.kemPub = newKemPub;
      [this.rootKey, this.ckSend] = await kdfRoot(this.rootKey, dhOut, kemSs);
      this.pn = this.nSend;
      this.nSend = 0;
    }

    async _ratchetRecvStep(header) {
      this.remoteDhPub = unb64(header.dh);
      this.remoteKemPub = unb64(header.kem_pub);
      const dhOut = dh(this.dhPriv, this.remoteDhPub);
      const kemCt = unb64(header.kem_ct);
      let kemSs;
      try {
        kemSs = await kemDecaps(this.kemAlg, this.kemPriv, kemCt);
      } catch (err) {
        if (!this.prevKemPriv || !this.prevKemPriv.length) throw err;
        kemSs = await kemDecaps(this.kemAlg, this.prevKemPriv, kemCt);
      }
      [this.rootKey, this.ckRecv] = await kdfRoot(this.rootKey, dhOut, kemSs);
      this.nRecv = 0;
      this.ckSend = null; // next encrypt() starts a fresh send epoch
    }

    async encrypt(plaintext) {
      if (this.ckSend === null) await this._ratchetSendStep();
      const [ck, mk] = await kdfChain(this.ckSend);
      this.ckSend = ck;
      const header = {
        dh: b64(this.dhPub),
        kem_pub: b64(this.kemPub),
        kem_ct: b64(this.sendKemCt),
        n: this.nSend,
        pn: this.pn,
      };
      this.nSend += 1;
      const envelope = {
        v: 1,
        header,
        ciphertext: b64(await msgEncrypt(mk, plaintext, canonicalHeader(header))),
      };
      if (this.handshake !== null) {
        envelope.init = this.handshake;
        this.handshake = null;
      }
      return envelope;
    }

    async decrypt(envelope) {
      const header = envelope.header;
      const ad = canonicalHeader(header);
      const ciphertext = unb64(envelope.ciphertext);

      const skipKey = `${header.dh}|${header.n}`;
      if (this.skipped.has(skipKey)) {
        const mk = this.skipped.get(skipKey);
        this.skipped.delete(skipKey);
        return msgDecrypt(mk, ciphertext, ad);
      }

      const sameEpoch = this.remoteDhPub !== null &&
        b64(this.remoteDhPub) === header.dh;
      if (!sameEpoch) {
        await this._skipMessageKeys(header.pn);
        await this._ratchetRecvStep(header);
      }
      await this._skipMessageKeys(header.n);

      const [ck, mk] = await kdfChain(this.ckRecv);
      this.ckRecv = ck;
      this.nRecv += 1;
      return msgDecrypt(mk, ciphertext, ad);
    }

    async _skipMessageKeys(until) {
      if (this.ckRecv === null) {
        if (until > 0) throw new Error("No receiving chain to skip into");
        return;
      }
      if (this.nRecv + MAX_SKIP < until) {
        throw new Error("Too many skipped messages");
      }
      const dhKey = b64(this.remoteDhPub);
      while (this.nRecv < until) {
        const [ck, mk] = await kdfChain(this.ckRecv);
        this.ckRecv = ck;
        this.skipped.set(`${dhKey}|${this.nRecv}`, mk);
        this.nRecv += 1;
        if (this.skipped.size > MAX_SKIP) {
          this.skipped.delete(this.skipped.keys().next().value);
        }
      }
    }

    toDict() {
      const opt = (v) => (v && v.length ? b64(v) : null);
      const skipped = [];
      for (const [key, mk] of this.skipped) {
        const sep = key.lastIndexOf("|");
        skipped.push({
          dh: key.slice(0, sep), n: parseInt(key.slice(sep + 1), 10), mk: b64(mk),
        });
      }
      return {
        kem_alg: this.kemAlg,
        root_key: b64(this.rootKey),
        dh_priv: opt(this.dhPriv),
        dh_pub: opt(this.dhPub),
        remote_dh_pub: this.remoteDhPub ? b64(this.remoteDhPub) : null,
        kem_priv: opt(this.kemPriv),
        kem_pub: opt(this.kemPub),
        prev_kem_priv: opt(this.prevKemPriv),
        remote_kem_pub: this.remoteKemPub ? b64(this.remoteKemPub) : null,
        send_kem_ct: opt(this.sendKemCt),
        ck_send: this.ckSend ? b64(this.ckSend) : null,
        ck_recv: this.ckRecv ? b64(this.ckRecv) : null,
        n_send: this.nSend,
        n_recv: this.nRecv,
        pn: this.pn,
        skipped,
        handshake: this.handshake,
      };
    }

    static fromDict(data) {
      const unopt = (v) => (v ? unb64(v) : new Uint8Array(0));
      const state = new TripleRatchet();
      state.kemAlg = data.kem_alg;
      state.rootKey = unb64(data.root_key);
      state.dhPriv = unopt(data.dh_priv);
      state.dhPub = unopt(data.dh_pub);
      state.remoteDhPub = data.remote_dh_pub ? unb64(data.remote_dh_pub) : null;
      state.kemPriv = unopt(data.kem_priv);
      state.kemPub = unopt(data.kem_pub);
      state.prevKemPriv = unopt(data.prev_kem_priv);
      state.remoteKemPub = data.remote_kem_pub ? unb64(data.remote_kem_pub) : null;
      state.sendKemCt = unopt(data.send_kem_ct);
      state.ckSend = data.ck_send ? unb64(data.ck_send) : null;
      state.ckRecv = data.ck_recv ? unb64(data.ck_recv) : null;
      state.nSend = data.n_send;
      state.nRecv = data.n_recv;
      state.pn = data.pn;
      state.skipped = new Map(
        (data.skipped || []).map((item) => [`${item.dh}|${item.n}`, unb64(item.mk)]),
      );
      state.handshake = data.handshake || null;
      return state;
    }
  }

  // -------------------------------------------------------------- vault ----
  // The vault key is derived from the passkey's PRF output; the host only
  // ever sees the resulting AES-GCM blobs.
  async function deriveVaultKey(prfOutput) {
    return hkdf(prfOutput, new Uint8Array(0), "omail-vault", 32);
  }
  async function vaultEncrypt(vaultKey, obj) {
    const iv = randomBytes(12);
    const key = await subtle.importKey("raw", vaultKey, "AES-GCM", false, ["encrypt"]);
    const ct = await subtle.encrypt(
      { name: "AES-GCM", iv }, key, te.encode(JSON.stringify(obj)),
    );
    return { v: 1, kdf: "prf-hkdf-v1", iv: b64(iv), ct: b64(new Uint8Array(ct)) };
  }
  async function vaultDecrypt(vaultKey, blob) {
    const key = await subtle.importKey("raw", vaultKey, "AES-GCM", false, ["decrypt"]);
    const pt = await subtle.decrypt(
      { name: "AES-GCM", iv: unb64(blob.iv) }, key, unb64(blob.ct),
    );
    return JSON.parse(td.decode(pt));
  }

  globalThis.OMailCrypto = {
    b64, unb64, b64url, unb64url, concat, randomBytes,
    hkdf, hmac, sha256,
    identityFromSeed, makePrekeyBundle, TripleRatchet,
    deriveVaultKey, vaultEncrypt, vaultDecrypt,
    PRF_EVAL_INPUT: te.encode("omail/vault-key/v1"),
  };
})();
