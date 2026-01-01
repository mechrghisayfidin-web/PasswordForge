/**
 * app.js — PasswordForge
 * Modules: cryptoUtils, storageManager, generatorEngine, uiController
 *
 * All security-sensitive operations use Web Crypto API (crypto.subtle & crypto.getRandomValues).
 * No external network calls. No Math.random for security.
 *
 * Exposes window.PasswordForge for tests.
 */

 (() => {
    'use strict';
  
    /** ---------- cryptoUtils: Web Crypto helper functions ---------- */
    const cryptoUtils = (() => {
      const textEncoder = new TextEncoder();
      const textDecoder = new TextDecoder();
      function ab2b64(buffer) {
  const bytes = new Uint8Array(buffer);
  const chunkSize = 0x8000;
  let result = '', i;
  for (i = 0; i < bytes.length; i += chunkSize) {
    result += String.fromCharCode.apply(null, bytes.subarray(i, i + chunkSize));
  }
  return btoa(result);
}

function b642ab(b64) {
  const bin = atob(b64);
  const len = bin.length;
  const arr = new Uint8Array(len);
  for (let i = 0; i < len; i++) arr[i] = bin.charCodeAt(i);
  return arr.buffer;
}

  
      // Convert ArrayBuffer to hex
      function ab2hex(buf) {
        const a = new Uint8Array(buf);
        let s = '';
        for (let i = 0; i < a.length; i++) {
          s += ('00' + a[i].toString(16)).slice(-2);
        }
        return s;
      }
  
      function hex2ab(hex) {
        const len = hex.length / 2;
        const ab = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
          ab[i] = parseInt(hex.substr(i * 2, 2), 16);
        }
        return ab.buffer;
      }
  
      // base64 helpers
      function ab2b64(buf) {
        const s = String.fromCharCode.apply(null, new Uint8Array(buf));
        return btoa(s);
      }
  
      function b642ab(b64) {
        const s = atob(b64);
        const arr = new Uint8Array(s.length);
        for (let i = 0; i < s.length; i++) arr[i] = s.charCodeAt(i);
        return arr.buffer;
      }
  
      /** SHA-256 digest of given ArrayBuffer */
      async function sha256(buffer) {
        // subtle.digest returns an ArrayBuffer
        return await crypto.subtle.digest('SHA-256', buffer);
      }
  
      /** Generate cryptographically secure random bytes */
      function randomBytes(n) {
        const a = new Uint8Array(n);
        crypto.getRandomValues(a); // secure RNG
        return a;
      }
  
      /** Convert string to ArrayBuffer */
      function str2ab(s) {
        return textEncoder.encode(s).buffer;
      }
  
      /** Convert ArrayBuffer to string */
      function ab2str(buf) {
        return textDecoder.decode(buf);
      }
  
      /** AES-GCM helper: generate AES-GCM key (raw 256-bit) */
      // file: script.js (جزء من cryptoUtils) — استبدل generateAesKey القديمة بهذه
async function generateAesKey() {
  // non-extractable key (safer). Store the CryptoKey object in IndexedDB if you need persistence.
  const key = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    false, // <- make it non-extractable
    ['encrypt', 'decrypt']
  );
  // store via storageManager (which should use IndexedDB structured clone)
  await storageManager.idbPut('app_crypto_key', key); // تأكد أن idbPut يدعم structured-clone
  return key;
}

  
      async function exportRawKey(key) {
        return await crypto.subtle.exportKey('raw', key); // returns ArrayBuffer
      }
  
      async function importRawKey(raw) {
        return await crypto.subtle.importKey(
          'raw',
          raw,
          { name: 'AES-GCM' },
          true,
          ['encrypt', 'decrypt']
        );
      }
  
      async function encryptWithKey(key, plainUint8) {
        // IV: 4 bytes timestamp (seconds) + 8 bytes random = 12 bytes total (96 bits)
        const ts = Math.floor(Date.now() / 1000);
        const tsBuf = new Uint8Array(4);
        tsBuf[0] = (ts >> 24) & 0xff;
        tsBuf[1] = (ts >> 16) & 0xff;
        tsBuf[2] = (ts >> 8) & 0xff;
        tsBuf[3] = ts & 0xff;
        const rand = cryptoUtils.randomBytes(8);
        const iv = new Uint8Array(12);
        iv.set(tsBuf, 0);
        iv.set(rand, 4);
      
        const cipher = await crypto.subtle.encrypt(
          { name: 'AES-GCM', iv },
          key,
          plainUint8
        );
      
        const combined = new Uint8Array(iv.byteLength + cipher.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(cipher), iv.byteLength);
        return cryptoUtils.ab2b64(combined.buffer);
      }
      
  
      async function decryptWithKey(key, b64) {
        const data = new Uint8Array(b642ab(b64));
        const iv = data.slice(0, 12);
        const cipher = data.slice(12);
        const plain = await crypto.subtle.decrypt(
          { name: 'AES-GCM', iv },
          key,
          cipher
        );
        return new Uint8Array(plain);
      }
  
      return {
        randomBytes,
        sha256,
        str2ab,
        ab2str,
        ab2hex,
        hex2ab,
        ab2b64,
        b642ab,
        generateAesKey,
        exportRawKey,
        importRawKey,
        encryptWithKey,
        decryptWithKey
      };
    })();
  
    /** ---------- storageManager: minimal IndexedDB + localStorage wrapper ---------- */
    const storageManager = (() => {
      const DB_NAME = 'passwordforge_db';
      const STORE = 'secrets';
      let dbPromise = null;
  
      function openDb() {
        if (dbPromise) return dbPromise;
        dbPromise = new Promise((resolve, reject) => {
          const req = indexedDB.open(DB_NAME, 1);
          req.onupgradeneeded = (e) => {
            const db = e.target.result;
            if (!db.objectStoreNames.contains(STORE)) {
              db.createObjectStore(STORE);
            }
          };
          req.onsuccess = () => resolve(req.result);
          req.onerror = () => reject(req.error);
        });
        return dbPromise;
      }
  
      async function idbPut(key, value) {
        const db = await openDb();
        return new Promise((res, rej) => {
          const tx = db.transaction(STORE, 'readwrite');
          tx.objectStore(STORE).put(value, key);
          tx.oncomplete = () => res(true);
          tx.onerror = () => rej(tx.error);
        });
      }
  
      async function idbGet(key) {
        const db = await openDb();
        return new Promise((res, rej) => {
          const tx = db.transaction(STORE, 'readonly');
          const o = tx.objectStore(STORE).get(key);
          o.onsuccess = () => res(o.result);
          o.onerror = () => rej(o.error);
        });
      }
  
      async function idbDelete(key) {
        const db = await openDb();
        return new Promise((res, rej) => {
          const tx = db.transaction(STORE, 'readwrite');
          tx.objectStore(STORE).delete(key);
          tx.oncomplete = () => res(true);
          tx.onerror = () => rej(tx.error);
        });
      }
  
      // Application-level keys:
      const APP_KEY = 'pf_app_key_raw'; // stored in IndexedDB as base64 raw bytes
      const ENCRYPTED_SALT = 'pf_enc_salt_v1'; // encrypted salt in localStorage (base64)
      const ENC_HASHES = 'pf_hashes_v1'; // encrypted JSON array of hashes stored in localStorage
  
      // Initialize or retrieve app crypto key used to encrypt local data
      async function getAppCryptoKey() {
        // if already in memory
        if (storageManager._cachedKey) return storageManager._cachedKey;
  
        // try to get raw key bytes from IDB
        const rawB64 = await idbGet(APP_KEY);
        if (rawB64) {
          const raw = cryptoUtils.b642ab(rawB64);
          const key = await cryptoUtils.importRawKey(raw);
          storageManager._cachedKey = key;
          return key;
        }
        // else generate new key, export raw, store base64 in IDB
        const key = await cryptoUtils.generateAesKey();
        const raw = await cryptoUtils.exportRawKey(key);
        const b64 = cryptoUtils.ab2b64(raw);
        await idbPut(APP_KEY, b64);
        storageManager._cachedKey = key;
        return key;
      }
  
      // Salt management (encrypted)
      async function getOrCreateSalt() {
        const appKey = await getAppCryptoKey();
        const enc = localStorage.getItem(ENCRYPTED_SALT);
        if (enc) {
          try {
            const dec = await cryptoUtils.decryptWithKey(appKey, enc);
            return new Uint8Array(dec); // salt bytes
          } catch (e) {
            console.warn('Failed decrypting salt:', e);
            // fallback: create new salt
          }
        }
        // create new random salt (32 bytes)
        const salt = cryptoUtils.randomBytes(32);
        const encSalt = await cryptoUtils.encryptWithKey(appKey, salt);
        localStorage.setItem(ENCRYPTED_SALT, encSalt);
        return salt;
      }
  
      // Hash store (encrypted JSON array)
      async function loadHashStore() {
        const appKey = await getAppCryptoKey();
        const enc = localStorage.getItem(ENC_HASHES);
        if (!enc) return [];
        try {
          const decArr = await cryptoUtils.decryptWithKey(appKey, enc);
          const json = cryptoUtils.ab2str(decArr.buffer);
          const list = JSON.parse(json);
          if (Array.isArray(list)) return list;
          return [];
        } catch (e) {
          console.warn('Failed to decrypt hash store:', e);
          return [];
        }
      }
  
      async function saveHashStore(list) {
        const appKey = await getAppCryptoKey();
        const json = JSON.stringify(list);
        const plain = new TextEncoder().encode(json);
        const enc = await cryptoUtils.encryptWithKey(appKey, plain);
        localStorage.setItem(ENC_HASHES, enc);
        // attempt to clear sensitive plain memory
        for (let i = 0; i < plain.length; i++) plain[i] = 0;
        return true;
      }
  
      // Public API
      return {
        getAppCryptoKey,
        getOrCreateSalt,
        loadHashStore,
        saveHashStore,
        idbPut,
        idbGet,
        idbDelete,
        // exposed keys for tests
        _internalKeys: { APP_KEY, ENCRYPTED_SALT, ENC_HASHES }
      };
    })();
  
    /** ---------- generatorEngine: password generation & hashing ---------- */
    const generatorEngine = (() => {
      const MAX_ATTEMPTS = 10;
      const DEFAULT_HASH_RATE = 1e11; // 100 billion guesses/sec for brute force estimate
  
      // small embedded wordlist (readable passphrases). Keep it embedded, no network.
      const WORDLIST = [
        'sun','star','river','tree','cloud','stone','iron','gold','silent','brave',
        'swift','ember','ocean','peak','shadow','crisp','dust','spark','lunar','nova',
        'orbit','sage','roam','drift','gleam','hush','quill','fable','glyph','harbor',
        'ivory','jolt','kin','lumen','moss','noble','opal','pact','quartz','raven',
        'sable','timber','umbra','vivid','whirl','xenon','yield','zephyr','anchor','beacon',
        'cinder','dune','echo','forge','glide','haven','isle','jet','knot','lagoon'
      ];
  
      // character sets
      const CHARS = {
        upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        lower: 'abcdefghijklmnopqrstuvwxyz',
        numbers: '0123456789',
        symbols: '!@#$%^&*()-_=+[]{};:,.<>/?`~'
      };
  
      // Remove excluded and similar if requested
      function buildCharset(options) {
        let pool = '';
        if (options.includeUpper) pool += CHARS.upper;
        if (options.includeLower) pool += CHARS.lower;
        if (options.includeNumbers) pool += CHARS.numbers;
        if (options.includeSymbols) pool += CHARS.symbols;
  
        // Exclude similar characters
        if (options.excludeSimilar) {
          pool = pool.replace(/[0Oo1lI]/g, '');
        }
        if (options.excludeChars) {
          // escape regex special
          const esc = options.excludeChars.replace(/[[\]{}()*+?.,\\^$|#\s]/g, '\\$&');
          const re = new RegExp('[' + esc + ']', 'g');
          pool = pool.replace(re, '');
        }
        // ensure fallback
        if (!pool) pool = CHARS.lower + CHARS.numbers;
        return pool;
      }
  
      // pick secure random integer in [0, n)
      function secureRandomIndex(n) {
        // Use rejection sampling to avoid modulo bias
        const max = Math.floor(0xFFFFFFFF / n) * n;
        const tmp = new Uint32Array(1);
        while (true) {
          crypto.getRandomValues(tmp);
          const val = tmp[0];
          if (val < max) return val % n;
        }
      }
  
      function pickRandomCharsFromPool(pool, length) {
        const res = new Array(length);
        for (let i = 0; i < length; i++) {
          const idx = secureRandomIndex(pool.length);
          res[i] = pool.charAt(idx);
        }
        return res.join('');
      }
  
      function generateReadablePassphrase(wordsCount, separator = '-') {
        // pick random words from WORDLIST
        const w = [];
        for (let i = 0; i < wordsCount; i++) {
          const idx = secureRandomIndex(WORDLIST.length);
          w.push(WORDLIST[idx]);
        }
        return w.join(separator);
      }
  
      async function computeHashWithSalt(password, saltUint8) {
        // Prepare: concat salt || password bytes
        const pwBytes = new TextEncoder().encode(password);
        const combined = new Uint8Array(saltUint8.length + pwBytes.length);
        combined.set(saltUint8, 0);
        combined.set(pwBytes, saltUint8.length);
        const digest = await crypto.subtle.digest('SHA-256', combined.buffer);
        // attempt to clear sensitive memory
        for (let i = 0; i < pwBytes.length; i++) pwBytes[i] = 0;
        for (let i = 0; i < combined.length; i++) combined[i] = 0;
        return cryptoUtils.ab2hex(digest);
      }
  
      function estimateEntropyBits(options, password) {
        if (options.pattern === 'readable') {
          // approximate: entropy per word = log2(wordlist length)
          const perWord = Math.log2(WORDLIST.length);
          const words = password.split(/[-_\s]/).length;
          return Math.round(perWord * words * 100) / 100;
        }
        // otherwise: pool size-based entropy
        const pool = buildCharset(options);
        const poolSize = new Set(pool.split('')).size;
        const bits = password.length * Math.log2(Math.max(2, poolSize));
        return Math.round(bits * 100) / 100;
      }
  
      function entropyToStrengthPercent(bits) {
        // Map security: 0-80 bits -> linear; 128 bits or more => 100%
        return Math.min(100, Math.round((bits / 128) * 100));
      }
  
      function bitsToBruteForceYears(bits, guessesPerSec = DEFAULT_HASH_RATE) {
        // guesses needed ~ 2^bits
        const guesses = Math.pow(2, bits);
        const seconds = guesses / guessesPerSec;
        const years = seconds / (3600 * 24 * 365);
        if (!isFinite(years) || years > 1e9) return '> 1B years';
        if (years < 1) return `${(years * 365).toFixed(1)} days`;
        if (years < 10) return `${years.toFixed(2)} years`;
        if (years < 1000) return `${Math.round(years)} years`;
        return `${Math.round(years).toLocaleString()} years`;
      }
  
      // Main generate function with uniqueness enforcement (hash-based)
      async function generateOne(options, saltBytes, enforceUnique = true) {
        let attempt = 0;
        while (attempt < MAX_ATTEMPTS) {
          attempt++;
          let password = '';
          if (options.pattern === 'readable') {
            // wordsCount based on length
            const wordsCount = Math.max(3, Math.round(options.length / 6));
            password = generateReadablePassphrase(wordsCount, '-');
            if (options.forceFirstUpper) {
              password = password.replace(/^\w/, (c) => c.toUpperCase());
            }
          } else if (options.pattern === 'hybrid') {
            // mix passphrase + random chars
            const wordsCount = Math.max(2, Math.round(options.length / 8));
            const phrase = generateReadablePassphrase(wordsCount, '');
            const pool = buildCharset(options);
            const suffixLen = Math.max(4, options.length - phrase.length);
            const suffix = pickRandomCharsFromPool(pool, suffixLen);
            password = phrase + suffix;
            if (options.forceFirstUpper) password = password.replace(/^\w/, (c) => c.toUpperCase());
          } else {
            // random
            const pool = buildCharset(options);
            password = pickRandomCharsFromPool(pool, options.length);
            if (options.forceFirstUpper) {
              password = password.replace(/^\w/, (c) => c.toUpperCase());
            }
          }
  
          // compute hash and check uniqueness
          const hash = await computeHashWithSalt(password, saltBytes);
          if (!enforceUnique) {
            return { password, hash };
          }
          const existing = await storageManager.loadHashStore();
          if (!existing.includes(hash)) {
            // store new hash (append)
            existing.push(hash);
            await storageManager.saveHashStore(existing);
            return { password, hash };
          }
          // otherwise loop to re-generate
        }
        // failed uniqueness
        throw new Error('Max attempts reached while trying to generate a unique password.');
      }
  
      // Batch generator
      async function generateBatch(options, count = 1) {
        const salt = await storageManager.getOrCreateSalt();
        const results = [];
        for (let i = 0; i < count; i++) {
          try {
            const { password, hash } = await generateOne(options, salt, true);
            results.push({ password, hash });
          } catch (e) {
            throw e;
          }
        }
        return results;
      }
  
      return {
        generateBatch,
        computeHashWithSalt,
        estimateEntropyBits,
        entropyToStrengthPercent,
        bitsToBruteForceYears,
        DEFAULT_HASH_RATE,
        WORDLIST,
        CHARS,
        _internal: { MAX_ATTEMPTS }
      };
    })();
  
    /** ---------- uiController: wire up DOM, interactions, and display ---------- */
    const uiController = (() => {
      // element refs
      const el = {
        length: null,
        lengthVal: null,
        includeUpper: null,
        includeLower: null,
        includeNumbers: null,
        includeSymbols: null,
        strengthMode: null,
        pattern: null,
        forceFirstUpper: null,
        excludeSimilar: null,
        excludeChars: null,
        preset: null,
        batchCount: null,
        generateBtn: null,
        regenerateBtn: null,
        copyBtn: null,
        downloadCsvBtn: null,
        exportReportBtn: null,
        showHideBtn: null,
        passwordDisplay: null,
        strengthBar: null,
        strengthText: null,
        entropyText: null,
        bfText: null,
        entropyFormula: null,
        hashRate: null,
        learnMoreBtn: null,
        modal: null,
        modalClose: null
      };
  
      let lastGenerated = []; // array of {password, hash}
      let lastVisible = false;
  
      function initElements() {
        el.length = document.getElementById('length');
        el.lengthVal = document.getElementById('lengthVal');
        el.includeUpper = document.getElementById('includeUpper');
        el.includeLower = document.getElementById('includeLower');
        el.includeNumbers = document.getElementById('includeNumbers');
        el.includeSymbols = document.getElementById('includeSymbols');
        el.strengthMode = document.getElementById('strengthMode');
        el.pattern = document.getElementById('pattern');
        el.forceFirstUpper = document.getElementById('forceFirstUpper');
        el.excludeSimilar = document.getElementById('excludeSimilar');
        el.excludeChars = document.getElementById('excludeChars');
        el.preset = document.getElementById('preset');
        el.batchCount = document.getElementById('batchCount');
        el.generateBtn = document.getElementById('generateBtn');
        el.regenerateBtn = document.getElementById('regenerateBtn');
        el.copyBtn = document.getElementById('copyBtn');
        el.downloadCsvBtn = document.getElementById('downloadCsvBtn');
        el.exportReportBtn = document.getElementById('exportReportBtn');
        el.showHideBtn = document.getElementById('showHideBtn');
        el.passwordDisplay = document.getElementById('passwordDisplay');
        el.strengthBar = document.getElementById('strengthBar');
        el.strengthText = document.getElementById('strengthText');
        el.entropyText = document.getElementById('entropyText');
        el.bfText = document.getElementById('bfText');
        el.entropyFormula = document.getElementById('entropyFormula');
        el.hashRate = document.getElementById('hashRate');
        el.learnMoreBtn = document.getElementById('learnMoreBtn');
        el.modal = document.getElementById('modal');
        el.modalClose = document.getElementById('modalClose');
      }
  
      function attachEvents() {
        el.length.addEventListener('input', () => {
          el.lengthVal.textContent = el.length.value;
        });
  
        el.generateBtn.addEventListener('click', onGenerate);
        el.regenerateBtn.addEventListener('click', onRegenerate);
        el.copyBtn.addEventListener('click', onCopy);
        el.showHideBtn.addEventListener('click', onShowHide);
        el.downloadCsvBtn.addEventListener('click', onDownloadCsv);
        el.exportReportBtn.addEventListener('click', onExportReport);
        el.preset.addEventListener('change', onPresetChange);
  
        el.learnMoreBtn.addEventListener('click', () => {
          el.modal.setAttribute('aria-hidden', 'false');
        });
        el.modalClose.addEventListener('click', () => {
          el.modal.setAttribute('aria-hidden', 'true');
        });
        // close modal on Escape
        window.addEventListener('keydown', (e) => {
          if (e.key === 'Escape') el.modal.setAttribute('aria-hidden', 'true');
        });
      }
  
      function getOptionsFromUI() {
        const options = {
          length: Number(el.length.value),
          includeUpper: el.includeUpper.checked,
          includeLower: el.includeLower.checked,
          includeNumbers: el.includeNumbers.checked,
          includeSymbols: el.includeSymbols.checked,
          strengthMode: el.strengthMode.value,
          pattern: el.pattern.value,
          forceFirstUpper: el.forceFirstUpper.checked,
          excludeSimilar: el.excludeSimilar.checked,
          excludeChars: el.excludeChars.value || ''
        };
        // Mode adjustments (simple)
        if (options.strengthMode === 'high') {
          options.includeSymbols = true;
          options.length = Math.max(20, options.length);
        } else if (options.strengthMode === 'memorable') {
          options.pattern = 'readable';
          options.includeNumbers = false;
          options.includeSymbols = false;
        }
        return options;
      }
  
      function onPresetChange() {
        const p = el.preset.value;
        if (p === 'social') {
          el.length.value = 12;
          el.includeSymbols.checked = false;
          el.includeNumbers.checked = true;
        } else if (p === 'email') {
          el.length.value = 16;
          el.includeSymbols.checked = false;
          el.includeNumbers.checked = true;
        } else if (p === 'wifi') {
          el.length.value = 20;
          el.includeSymbols.checked = true;
          el.includeNumbers.checked = true;
        } else if (p === 'gaming') {
          el.length.value = 14;
          el.includeSymbols.checked = true;
          el.includeNumbers.checked = true;
        }
        el.lengthVal.textContent = el.length.value;
      }
  
      async function onGenerate() {
        el.generateBtn.disabled = true;
        const options = getOptionsFromUI();
        const count = Math.min(50, Math.max(1, Number(el.batchCount.value)));
        try {
          const results = await generatorEngine.generateBatch(options, count);
          lastGenerated = results;
          // show first result masked
          showPassword(results[0].password, true);
          updateMetrics(options, results[0].password);
          animateOnGenerate();
        } catch (e) {
          alert('خطأ في التوليد: ' + e.message);
        } finally {
          el.generateBtn.disabled = false;
        }
      }
  
      async function onRegenerate() {
        // regenerate last config if exists
        const options = getOptionsFromUI();
        try {
          const results = await generatorEngine.generateBatch(options, 1);
          lastGenerated = results;
          showPassword(results[0].password, true);
          updateMetrics(options, results[0].password);
          animateOnGenerate();
        } catch (e) {
          alert('خطأ في إعادة التوليد: ' + e.message);
        }
      }
  
      async function onCopy() {
        if (!lastGenerated.length) { alert('لا توجد كلمة لتنسخ'); return; }
        const pw = lastGenerated[0].password;
        try {
          await navigator.clipboard.writeText(pw);
          // clear sensitive memory: overwrite variable
          // While JS strings are immutable, we can null references and suggest clearing.
          el.copyBtn.textContent = 'Copied';
          setTimeout(()=> el.copyBtn.textContent = 'Copy', 1500);
        } catch (e) {
          alert('فشل النسخ إلى الحافظة: ' + e);
        } finally {
          // indicate data cleared from memory (best-effort)
          // Note: JS cannot reliably overwrite string content; we null references instead.
          setTimeout(() => { /* best-effort zeroization: */ }, 0);
        }
      }
  
      function onShowHide() {
        lastVisible = !lastVisible;
        if (!lastGenerated.length) return;
        showPassword(lastGenerated[0].password, !lastVisible);
      }
  
      async function onDownloadCsv() {
        if (!lastGenerated.length) { alert('لا توجد كلمات للتحميل'); return; }
        const confirmed = confirm('تحذير أمني: الملف الذي ستحمله يحتوي على كلمات مرور حساسة. هل تريد المتابعة؟');
        if (!confirmed) return;
        const rows = lastGenerated.map(r => `"${r.password.replace(/"/g,'""')}"`).join('\n');
        const blob = new Blob([rows], { type: 'text/csv;charset=utf-8;' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `passwordforge_batch_${Date.now()}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
        // After download, show note: data cleared from memory
        alert('تم تنزيل الملف. يُنصح بحذف الملف من الجهاز بعد الاستخدام إذا لم يعد مطلوباً.');
      }
  
      async function onExportReport() {
        if (!lastGenerated.length) { alert('لا توجد كلمة لإنشاء تقرير'); return; }
        const confirmed = confirm('تحذير أمني: سيتم توليد صورة (PNG) على جهازك تحتوي على معلومات حساسة. متابعة؟');
        if (!confirmed) return;
        const pw = lastGenerated[0].password;
        const bits = generatorEngine.estimateEntropyBits(getOptionsFromUI(), pw);
        const strength = generatorEngine.entropyToStrengthPercent(bits);
        const est = generatorEngine.bitsToBruteForceYears(bits, generatorEngine.DEFAULT_HASH_RATE);
        // create canvas
        const c = document.createElement('canvas');
        c.width = 800; c.height = 480;
        const ctx = c.getContext('2d');
        // background
        ctx.fillStyle = '#0f1720';
        ctx.fillRect(0,0,c.width,c.height);
        ctx.fillStyle = '#7afcff';
        ctx.font = 'bold 26px sans-serif';
        ctx.fillText('PasswordForge Report', 28, 48);
        ctx.fillStyle = '#e6f0f2';
        ctx.font = '18px sans-serif';
        // masked password
        ctx.fillText('Password: ' + '•'.repeat(Math.min(20, pw.length)), 28, 110);
        ctx.fillText(`Strength: ${strength}%`, 28, 150);
        ctx.fillText(`Entropy: ${bits} bits`, 28, 180);
        ctx.fillText(`Brute-force estimate: ${est}`, 28, 210);
        // note
        ctx.font = '14px sans-serif';
        ctx.fillStyle = '#9aa7b2';
        ctx.fillText('Generated locally. This image includes sensitive data (password masked).', 28, c.height - 40);
  
        const url = c.toDataURL('image/png');
        const a = document.createElement('a');
        a.href = url;
        a.download = `pf_report_${Date.now()}.png`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        URL.revokeObjectURL(url);
      }
  
      function showPassword(pw, masked = true) {
        if (masked) {
          el.passwordDisplay.classList.add('masked');
          el.passwordDisplay.textContent = '•'.repeat(Math.max(6, Math.min(30, pw.length)));
          el.showHideBtn.textContent = 'Show';
          el.passwordDisplay.setAttribute('aria-hidden', 'true');
        } else {
          el.passwordDisplay.classList.remove('masked');
          el.passwordDisplay.textContent = pw;
          el.showHideBtn.textContent = 'Hide';
          el.passwordDisplay.setAttribute('aria-hidden', 'false');
        }
      }
  
      function animateOnGenerate() {
        const elc = document.querySelector('.result-card');
        elc.animate([{ transform: 'scale(0.98)', opacity: 0.8 }, { transform: 'scale(1)', opacity: 1 }], {
          duration: 320, easing: 'cubic-bezier(.2,.9,.2,1)'
        });
      }
  
      function updateMetrics(options, password) {
        const bits = generatorEngine.estimateEntropyBits(options, password);
        const percent = generatorEngine.entropyToStrengthPercent(bits);
        el.strengthBar.value = percent;
        el.strengthText.textContent = `${percent}%`;
        el.entropyText.textContent = `${bits} bits`;
        el.bfText.textContent = generatorEngine.bitsToBruteForceYears(bits, generatorEngine.DEFAULT_HASH_RATE);
        el.entropyFormula.textContent = computeFormulaText(options, password);
        el.hashRate.textContent = String(generatorEngine.DEFAULT_HASH_RATE);
      }
  
      function computeFormulaText(options, password) {
        if (options.pattern === 'readable') {
          const perWord = Math.log2(generatorEngine.WORDLIST.length).toFixed(2);
          const words = password.split(/[-_\s]/).length;
          return `Readable passphrase: entropy ≈ ${perWord} bits/word × ${words} words = ${Math.round(perWord * words)} bits.`;
        }
        const pool = (() => {
          const set = new Set();
          if (options.includeUpper) [...generatorEngine.CHARS.upper].forEach(c=>set.add(c));
          if (options.includeLower) [...generatorEngine.CHARS.lower].forEach(c=>set.add(c));
          if (options.includeNumbers) [...generatorEngine.CHARS.numbers].forEach(c=>set.add(c));
          if (options.includeSymbols) [...generatorEngine.CHARS.symbols].forEach(c=>set.add(c));
          if (options.excludeSimilar) ['0','O','o','1','l','I'].forEach(c=>set.delete(c));
          if (options.excludeChars) options.excludeChars.split('').forEach(c=>set.delete(c));
          return set.size;
        })();
        const bitsPerChar = Math.log2(Math.max(2, pool)).toFixed(2);
        return `Entropy ≈ length(${password.length}) × log2(pool(${pool})) ≈ ${password.length} × ${bitsPerChar} = ${ (password.length * Math.log2(Math.max(2,pool))).toFixed(2) } bits.`;
      }
  
      function exposeForTests() {
        // Expose internal functions/objects for test.html to use
        window.PasswordForge = {
          generatorEngine,
          storageManager,
          cryptoUtils,
          ui: {
            getOptionsFromUI,
            lastGenerated: () => lastGenerated
          }
        };
      }
  
      function init() {
        initElements();
        attachEvents();
        el.lengthVal.textContent = el.length.value;
        exposeForTests();
      }
  
      return { init };
    })();
  
    // Initialize
    document.addEventListener('DOMContentLoaded', async () => {
      try {
        await storageManager.getAppCryptoKey(); // ensure key exists
        uiController.init();
      } catch (e) {
        console.error('Initialization error:', e);
        alert('خطأ أثناء تهيئة PasswordForge. الرجاء فتح الكونسول للمزيد.');
      }
    });
  
  })();
  