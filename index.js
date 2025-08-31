/**
 * UPFASTTIX — Very-strong form validator (index.js)
 *
 * - All fields optional: if provided they are validated strictly.
 * - Fields supported: name, email, phone, dob (ISO or dd/mm/yyyy - parsed), password, confirmPassword,
 *   url, number, custom fields via rules.
 * - DOB must be >= minAge (default 18) when provided.
 * - Password: strong checks + entropy estimate + small local common-password blacklist.
 * - Phone normalization attempts E.164-like output. Default locale 'IN' (adds +91 for 10-digit IN numbers).
 * - Privacy: no raw password logging; supports injecting a hashing function (async) to return hashedPassword.
 *
 * Usage:
 * const { validate, utils } = require('./index');
 * const result = await validate(formObject, options);
 *
 * Returns: { valid: boolean, errors: { field: [messages] }, cleaned: { field: value }, meta: {...} }
 */

const DEFAULTS = {
  locale: "IN",
  sanitize: true,
  minAge: 18,
  password: {
    minLength: 12,
    minEntropyBits: 60,
    require: { upper: true, lower: true, digit: true, special: true }
  },
  rules: {}, // per-field rule overrides
  // For production, inject a secure async passwordHash function that returns { hash, algo } to avoid storing raw passwords.
  // Example: options.passwordHash = async (plain) => ({ hash: await bcrypt.hash(plain, 12), algo: 'bcrypt' })
  passwordHash: null,
  // Optional HMAC secret for cross-checks: { key: 'abc', algo: 'sha256' } or provide a function to compute.
  hmacSecret: null
};

// --- Utilities & helpers ---
const isNode = typeof process !== "undefined" && process.versions && process.versions.node;
const cryptoNode = isNode ? require("crypto") : null;

// Basic safe trim
const trimStr = s => (typeof s === "string" ? s.trim() : s);

// Escape HTML for cleaned output to reduce XSS risk (output only)
const escapeHtml = s =>
  String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");

// Constant-time string compare to avoid timing attacks
function constantTimeEqual(a = "", b = "") {
  try {
    if (cryptoNode && cryptoNode.timingSafeEqual) {
      const bufA = Buffer.from(String(a), "utf8");
      const bufB = Buffer.from(String(b), "utf8");
      if (bufA.length !== bufB.length) {
        // still perform a timing-safe op using padded buffers to avoid leaking length easily
        const pad = Buffer.alloc(Math.max(bufA.length, bufB.length));
        const A = Buffer.concat([bufA, pad], pad.length + bufA.length);
        const B = Buffer.concat([bufB, pad], pad.length + bufB.length);
        return cryptoNode.timingSafeEqual(A, B);
      }
      return cryptoNode.timingSafeEqual(bufA, bufB);
    }
  } catch (e) {
    // fallback to JS implementation
  }
  // JS fallback constant-time
  const A = String(a);
  const B = String(b);
  let diff = A.length ^ B.length;
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const ca = A.charCodeAt(i) || 0;
    const cb = B.charCodeAt(i) || 0;
    diff |= ca ^ cb;
  }
  return diff === 0;
}

// --- Regexes / validators ---
const EMAIL_RE = /^[^\s@]{1,256}@[^\s@]{1,256}\.[^\s@]{2,}$/i;
const E164_RE = /^\+?[1-9]\d{7,14}$/; // permissive E.164-ish
const URL_RE = /^(https?:\/\/)?([^\s./]+\.)+[^\s]{2,}(\/\S*)?$/i;
const NAME_BAD_CHARS = /[^a-zA-Z\u00C0-\u024f0-9' \-\.]/; // allow letters, digits, apostrophe, hyphen, dot, spaces
const COMMON_PW = new Set([
  // small blacklist (add more in production)
  "123456", "password", "123456789", "qwerty", "abc123", "111111", "1234567", "letmein", "monkey", "dragon"
]);

// Estimate entropy (bits) — conservative approximation based on char classes + length penalties
function estimateEntropy(password) {
  if (!password || typeof password !== "string") return 0;
  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/\d/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;
  const rawEntropy = Math.log2(Math.max(1, pool)) * password.length;
  // penalize common sequences and repetitions
  const hasRepeat = /(.)\1{2,}/.test(password);
  const hasDictionary = COMMON_PW.has(password.toLowerCase());
  let factor = 1;
  if (hasRepeat) factor *= 0.7;
  if (hasDictionary) factor *= 0.2;
  return Math.round(Math.max(0, rawEntropy * factor));
}

// DOB parser: accepts ISO YYYY-MM-DD, or dd/mm/yyyy or mm/dd/yyyy if configured; returns { ok, date: Date, age }
function parseDob(value) {
  if (!value) return { ok: false };
  const v = String(value).trim();
  // Try ISO first
  const isoMatch = v.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (isoMatch) {
    const y = Number(isoMatch[1]), m = Number(isoMatch[2]) - 1, d = Number(isoMatch[3]);
    const dt = new Date(Date.UTC(y, m, d));
    if (isNaN(dt)) return { ok: false };
    return { ok: true, date: dt, age: calcAge(dt) };
  }
  // Try dd/mm/yyyy or dd-mm-yyyy
  const dmy = v.match(/^(\d{1,2})[\/\-](\d{1,2})[\/\-](\d{4})$/);
  if (dmy) {
    const d = Number(dmy[1]), m = Number(dmy[2]) - 1, y = Number(dmy[3]);
    const dt = new Date(Date.UTC(y, m, d));
    if (isNaN(dt)) return { ok: false };
    return { ok: true, date: dt, age: calcAge(dt) };
  }
  // Fallback: try Date parse (less strict)
  const fallback = new Date(v);
  if (!isNaN(fallback)) return { ok: true, date: fallback, age: calcAge(fallback) };
  return { ok: false };
}

function calcAge(birthDate) {
  const now = new Date();
  // Calculate age using local timezone to be conservative
  let age = now.getUTCFullYear() - birthDate.getUTCFullYear();
  const m = now.getUTCMonth() - birthDate.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < birthDate.getUTCDate())) age--;
  return age;
}

// Phone validator + normalizer (locale smart)
function validatePhone(value, locale = "IN") {
  if (value === null || value === undefined || value === "") return { ok: false };
  let raw = String(value).trim();
  // strip spaces, parentheses, dashes, dots, but keep leading +
  raw = raw.replace(/[ \-\.\(\)]/g, "");
  // if starts with 0 and locale IN -> convert to +91...
  if (/^0\d{9,}$/.test(raw) && locale && locale.toUpperCase() === "IN") {
    raw = "+91" + raw.replace(/^0+/, "");
  }
  // if 10 digits and IN, add +91
  if (/^\d{10}$/.test(raw) && locale && locale.toUpperCase() === "IN") {
    raw = "+91" + raw;
  }
  // E164-ish check
  const ok = E164_RE.test(raw) && raw.length >= 8 && raw.length <= 16;
  return { ok, normalized: ok ? (raw.startsWith("+") ? raw : "+" + raw) : raw };
}

// Email validator + normalizer
function validateEmail(value) {
  if (!value || typeof value !== "string") return { ok: false };
  const v = value.trim();
  if (!EMAIL_RE.test(v)) return { ok: false };
  // Additional domain label checks
  const parts = v.split("@");
  if (parts.length !== 2) return { ok: false };
  const [local, domain] = parts;
  if (local.length > 64 || domain.length > 255) return { ok: false };
  if (local.startsWith(".") || local.endsWith(".")) return { ok: false };
  // Lowercase domain for normalization
  const normalized = `${local}@${domain.toLowerCase()}`;
  return { ok: true, normalized };
}

// Name validator
function validateName(value, opts = {}) {
  if (value === null || value === undefined || value === "") return { ok: false };
  const raw = String(value).trim();
  const min = opts.min || 2;
  const max = opts.max || 80;
  if (raw.length < min || raw.length > max) return { ok: false, sanitized: raw };
  if (NAME_BAD_CHARS.test(raw)) return { ok: false, sanitized: raw };
  // Collapse multiple spaces
  const sanitized = raw.replace(/\s{2,}/g, " ");
  return { ok: true, sanitized };
}

// Number parsing validator
function validateNumber(value, opts = {}) {
  if (value === null || value === undefined || value === "") return { ok: false };
  const n = Number(value);
  if (!isFinite(n)) return { ok: false };
  if (typeof opts.min === "number" && n < opts.min) return { ok: false };
  if (typeof opts.max === "number" && n > opts.max) return { ok: false };
  return { ok: true, parsed: n };
}

// URL check
function validateUrl(value) {
  if (!value || typeof value !== "string") return { ok: false };
  const v = value.trim();
  if (!URL_RE.test(v)) return { ok: false };
  const normalized = v.startsWith("http://") || v.startsWith("https://") ? v : "https://" + v;
  return { ok: true, normalized };
}

// Password validator (strong)
function validatePassword(value, passwordCfg = DEFAULTS.password) {
  if (!value || typeof value !== "string") return { ok: false, reason: "not_string" };
  const pw = value;
  if (pw.length < passwordCfg.minLength) return { ok: false, reason: "too_short", length: pw.length };
  const hasUpper = /[A-Z]/.test(pw);
  const hasLower = /[a-z]/.test(pw);
  const hasDigit = /\d/.test(pw);
  const hasSpecial = /[^A-Za-z0-9]/.test(pw);
  if (passwordCfg.require.upper && !hasUpper) return { ok: false, reason: "need_upper" };
  if (passwordCfg.require.lower && !hasLower) return { ok: false, reason: "need_lower" };
  if (passwordCfg.require.digit && !hasDigit) return { ok: false, reason: "need_digit" };
  if (passwordCfg.require.special && !hasSpecial) return { ok: false, reason: "need_special" };
  if (COMMON_PW.has(pw.toLowerCase())) return { ok: false, reason: "common_password" };
  const entropy = estimateEntropy(pw);
  if (entropy < passwordCfg.minEntropyBits) return { ok: false, reason: "low_entropy", entropy };
  return { ok: true, entropy };
}

// Auto-detect field type
function detectFieldType(key, value) {
  const k = String(key).toLowerCase();
  if (/(email|e-mail)/.test(k) || (typeof value === "string" && EMAIL_RE.test(value))) return "email";
  if (/(phone|mobile|tel|contact)/.test(k) || (typeof value === "string" && E164_RE.test(value))) return "phone";
  if (/(pass|pwd|password)/.test(k)) return "password";
  if (/(confirm|confirm_password|password_confirm)/.test(k)) return "confirmPassword";
  if (/(name|fullname|first_name|last_name)/.test(k)) return "name";
  if (/(dob|dateofbirth|birth|birthdate)/.test(k)) return "dob";
  if (/(url|website|link)/.test(k)) return "url";
  if (/(age|amount|price|quantity|number|num|count)/.test(k) || typeof value === "number") return "number";
  return "text";
}

// --- Main validate function ---
/**
 * validate(formObject, options) -> Promise resolving to validation result
 * options: merges with DEFAULTS
 * Returns: { valid, errors, cleaned, meta }
 */
async function validate(form = {}, options = {}) {
  const cfg = deepMerge(DEFAULTS, options || {});
  const errors = {};
  const cleaned = {};
  const meta = { validatedAt: new Date().toISOString(), fieldsValidated: [] };

  // iterate fields
  for (const rawKey of Object.keys(form)) {
    const key = String(rawKey);
    const rawValue = form[rawKey];
    const ruleOverride = cfg.rules && cfg.rules[key] ? cfg.rules[key] : null;
    const detected = ruleOverride && ruleOverride.type ? ruleOverride.type : detectFieldType(key, rawValue);

    meta.fieldsValidated.push({ key, detected });

    // If value is null/empty string/undefined => skip validation (optional)
    if (rawValue === null || rawValue === undefined || (typeof rawValue === "string" && rawValue.trim() === "")) {
      // optional: not present, so don't include in cleaned or errors
      continue;
    }

    // apply sanitization for strings early (trim)
    let value = typeof rawValue === "string" ? rawValue.trim() : rawValue;

    switch (detected) {
      case "email": {
        const r = validateEmail(value);
        if (!r.ok) addError(errors, key, "invalid_email");
        else cleaned[key] = cfg.sanitize ? escapeHtml(r.normalized) : r.normalized;
        break;
      }
      case "phone": {
        const r = validatePhone(value, cfg.locale);
        if (!r.ok) addError(errors, key, "invalid_phone");
        else cleaned[key] = cfg.sanitize ? escapeHtml(r.normalized) : r.normalized;
        break;
      }
      case "dob": {
        const r = parseDob(value);
        if (!r.ok) {
          addError(errors, key, "invalid_dob");
        } else {
          const age = r.age;
          if (typeof cfg.minAge === "number" && age < cfg.minAge) {
            addError(errors, key, `age_must_be_at_least_${cfg.minAge}`);
            // still include sanitized date if you want
            cleaned[key] = cfg.sanitize ? escapeHtml(r.date.toISOString().slice(0, 10)) : r.date.toISOString().slice(0, 10);
          } else {
            cleaned[key] = cfg.sanitize ? escapeHtml(r.date.toISOString().slice(0, 10)) : r.date.toISOString().slice(0, 10);
          }
        }
        break;
      }
      case "password": {
        // Password should not be placed in cleaned raw; but we validate and optionally provide hashed value via passwordHash
        const r = validatePassword(value, cfg.password);
        if (!r.ok) {
          addError(errors, key, r.reason || "invalid_password");
        } else {
          // If passwordHash provided, compute hash and return hash in cleaned as `passwordHash`
          if (typeof cfg.passwordHash === "function") {
            try {
              // allow async or sync
              const out = await cfg.passwordHash(value);
              if (out && out.hash) {
                cleaned[`${key}Hash`] = out.hash;
                if (out.algo) cleaned[`${key}HashAlgo`] = out.algo;
                // Important: do NOT include raw password in cleaned
              } else {
                // fallback: do not include anything
              }
            } catch (e) {
              // hashing failed — do not propagate raw password, just error
              addError(errors, key, "password_hash_failed");
            }
          } else {
            // No hashing supplied: DO NOT include raw password in cleaned. Instead mark validated.
            cleaned[`${key}Validated`] = true;
          }
        }
        break;
      }
      case "confirmPassword": {
        // confirmPassword should match password only if password present
        const passwordValue = form.password || form.pass || form.pwd;
        if (typeof passwordValue === "undefined" || passwordValue === null || passwordValue === "") {
          // No password provided => ignore confirmPassword (optional)
          continue;
        }
        const same = constantTimeEqual(String(value), String(passwordValue));
        if (!same) addError(errors, key, "password_mismatch");
        else cleaned[key] = true;
        break;
      }
      case "name": {
        const r = validateName(value);
        if (!r.ok) addError(errors, key, "invalid_name");
        else cleaned[key] = cfg.sanitize ? escapeHtml(r.sanitized) : r.sanitized;
        break;
      }
      case "url": {
        const r = validateUrl(value);
        if (!r.ok) addError(errors, key, "invalid_url");
        else cleaned[key] = cfg.sanitize ? escapeHtml(r.normalized) : r.normalized;
        break;
      }
      case "number": {
        const r = validateNumber(value, (ruleOverride && ruleOverride.number) || {});
        if (!r.ok) addError(errors, key, "invalid_number");
        else cleaned[key] = r.parsed;
        break;
      }
      default: {
        // text: apply maxLength if present in ruleOverride, otherwise default 2000
        if (typeof value === "string") {
          const max = (ruleOverride && ruleOverride.maxLength) || 2000;
          if (value.length > max) addError(errors, key, "too_long");
          else cleaned[key] = cfg.sanitize ? escapeHtml(value) : value;
        } else {
          cleaned[key] = value;
        }
      }
    } // switch
  } // for

  // cross-field checks
  if ("password" in form) {
    // if confirm provided, it was validated above; otherwise check confirm naming patterns
    const confirmKeys = ["confirmPassword", "confirm_password", "passwordConfirm", "password_confirm"];
    for (const ck of confirmKeys) {
      if (ck in form && form[ck] !== null && form[ck] !== undefined && String(form[ck]).trim() !== "") {
        // compare with constant-time
        if (!constantTimeEqual(String(form.password || ""), String(form[ck] || ""))) {
          addError(errors, ck, "password_mismatch");
        }
      }
    }
  }

  const valid = Object.keys(errors).length === 0;
  return { valid, errors, cleaned, meta };
}

// --- small helpers ---
function addError(errorsObj, field, message) {
  if (!errorsObj[field]) errorsObj[field] = [];
  errorsObj[field].push(message);
}

// deep merge for defaults (simple)
function deepMerge(a, b) {
  const out = JSON.parse(JSON.stringify(a));
  for (const k of Object.keys(b || {})) {
    if (b[k] && typeof b[k] === "object" && !Array.isArray(b[k]) && out[k] && typeof out[k] === "object") {
      out[k] = deepMerge(out[k], b[k]);
    } else {
      out[k] = b[k];
    }
  }
  return out;
}

// Export utilities for testing & extension
const utils = {
  estimateEntropy,
  validateEmail,
  validatePhone,
  validatePassword,
  parseDob,
  validateName,
  constantTimeEqual
};

// Export
module.exports = { validate, utils, DEFAULTS };

/* -------------------------
  Notes & production hardening suggestions:
  - Replace the small COMMON_PW set with a larger breached-password list or integrate with
    a service like HaveIBeenPwned's Pwned Passwords API (use k-anonymity model).
  - For phone validation at scale, use libphonenumber-js to parse and validate international numbers precisely.
  - Provide a secure server-side passwordHash function (bcrypt/argon2) via options.passwordHash so raw passwords never appear in logs or memory stores.
  - Consider rate-limiting validation attempts by IP to prevent online brute-force (done at API layer).
  - Use TLS everywhere and treat cleaned outputs as pre-validated input (still apply server-side database constraints and hashing).
  - If you need HMAC validation (for form integrity), provide options.hmacCompute function and compare using constantTimeEqual.
-------------------------- */
