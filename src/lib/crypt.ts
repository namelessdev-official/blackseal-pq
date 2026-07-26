import { argon2id } from "hash-wasm";

/**
 * .crypt container format — v1
 * ---------------------------------------------------------------
 * All multi-byte integers are little-endian.
 *
 *  off  len  field
 *   0    5   magic            "CRYPT"
 *   5    1   version          0x01
 *   6    1   kdf id           0x01 = Argon2id
 *   7    1   cipher id        0x01 = AES-256-GCM cascade (x2)
 *   8    4   memory (KiB)     uint32
 *  12    4   iterations       uint32
 *  16    1   parallelism      uint8
 *  17    1   flags            reserved
 *  18   32   salt             CSPRNG
 *  50   12   nonce A (outer)  CSPRNG
 *  62   12   nonce B (inner)  CSPRNG
 *  74    4   body length      uint32
 *  ---- 78 bytes of header, authenticated as AAD by BOTH cipher layers ----
 *  78    n   body             outer_ct || outer_tag
 *
 * Plaintext (before the inner layer) is:
 *   uint32 realLength || CBOR-ish JSON payload || CSPRNG padding
 * padded up to a multiple of PAD_BLOCK so the file size never leaks the
 * true length of the message or the identity.
 */

export const MAGIC = new Uint8Array([0x43, 0x52, 0x59, 0x50, 0x54]); // "CRYPT"
export const VERSION = 1;
export const HEADER_LEN = 78;
const PAD_BLOCK = 512;

export type ProfileId = "standard" | "hardened" | "paranoid";

export interface KdfParams {
  memoryKiB: number;
  iterations: number;
  parallelism: number;
}

export interface Profile extends KdfParams {
  id: ProfileId;
  name: string;
  blurb: string;
  approxTime: string;
}

export const PROFILES: Record<ProfileId, Profile> = {
  standard: {
    id: "standard",
    name: "STANDARD",
    memoryKiB: 65536, // 64 MiB
    iterations: 3,
    parallelism: 1,
    blurb: "64 MiB · 3 passes — strong against GPU farms, fast on phones.",
    approxTime: "~1s",
  },
  hardened: {
    id: "hardened",
    name: "HARDENED",
    memoryKiB: 262144, // 256 MiB
    iterations: 4,
    parallelism: 1,
    blurb: "256 MiB · 4 passes — ASIC/FPGA cracking becomes economically absurd.",
    approxTime: "~4s",
  },
  paranoid: {
    id: "paranoid",
    name: "PARANOID",
    memoryKiB: 786432, // 768 MiB
    iterations: 8,
    parallelism: 1,
    blurb: "768 MiB · 8 passes — one guess costs a server-second. Nation-state grade.",
    approxTime: "~20s+",
  },
};

export interface Payload {
  /** identity / signature of the sender */
  from: string;
  /** the secret message */
  msg: string;
  /** unix ms the message was sealed */
  ts: number;
  /** optional note visible only after decryption */
  note?: string;
}

export interface SealedMeta {
  version: number;
  kdf: string;
  cipher: string;
  params: KdfParams;
  bodyLength: number;
  totalLength: number;
  salt: Uint8Array;
}

const enc = new TextEncoder();
const dec = new TextDecoder();

export function randomBytes(n: number): Uint8Array {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return b;
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n >>> 0, true);
  return b;
}

function readU32(b: Uint8Array, off: number): number {
  return new DataView(b.buffer, b.byteOffset, b.byteLength).getUint32(off, true);
}

async function importKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

/** Argon2id -> 64 bytes -> two independent 256-bit cipher keys. */
async function deriveKeys(
  password: string,
  salt: Uint8Array,
  p: KdfParams,
): Promise<{ kOuter: CryptoKey; kInner: CryptoKey }> {
  const raw = (await argon2id({
    password,
    salt,
    parallelism: p.parallelism,
    iterations: p.iterations,
    memorySize: p.memoryKiB,
    hashLength: 64,
    outputType: "binary",
  })) as Uint8Array;

  const kOuter = await importKey(raw.slice(0, 32));
  const kInner = await importKey(raw.slice(32, 64));
  raw.fill(0);
  return { kOuter, kInner };
}

function pad(data: Uint8Array): Uint8Array {
  const total = Math.max(
    PAD_BLOCK,
    Math.ceil((data.length + 4) / PAD_BLOCK) * PAD_BLOCK,
  );
  const out = randomBytes(total);
  out.set(u32le(data.length), 0);
  out.set(data, 4);
  return out;
}

function unpad(data: Uint8Array): Uint8Array {
  const len = readU32(data, 0);
  if (len > data.length - 4) throw new Error("PADDING_CORRUPT");
  return data.slice(4, 4 + len);
}

export interface SealResult {
  bytes: Uint8Array;
  meta: SealedMeta;
}

export async function seal(
  payload: Payload,
  password: string,
  params: KdfParams,
): Promise<SealResult> {
  const salt = randomBytes(32);
  const nonceA = randomBytes(12);
  const nonceB = randomBytes(12);

  const plain = pad(enc.encode(JSON.stringify(payload)));

  // Body length is not known until after encryption, but AES-GCM output size is
  // deterministic: padded length + 16 (inner tag) + 16 (outer tag).
  const bodyLength = plain.length + 32;

  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[5] = VERSION;
  header[6] = 0x01; // argon2id
  header[7] = 0x01; // aes-256-gcm cascade
  header.set(u32le(params.memoryKiB), 8);
  header.set(u32le(params.iterations), 12);
  header[16] = params.parallelism;
  header[17] = 0x00;
  header.set(salt, 18);
  header.set(nonceA, 50);
  header.set(nonceB, 62);
  header.set(u32le(bodyLength), 74);

  const { kOuter, kInner } = await deriveKeys(password, salt, params);

  const inner = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceB as BufferSource, additionalData: header as BufferSource, tagLength: 128 },
      kInner,
      plain as BufferSource,
    ),
  );
  const outer = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonceA as BufferSource, additionalData: header as BufferSource, tagLength: 128 },
      kOuter,
      inner as BufferSource,
    ),
  );
  plain.fill(0);

  const file = new Uint8Array(HEADER_LEN + outer.length);
  file.set(header, 0);
  file.set(outer, HEADER_LEN);

  return {
    bytes: file,
    meta: inspect(file),
  };
}

export function inspect(file: Uint8Array): SealedMeta {
  if (file.length < HEADER_LEN + 32) throw new Error("TOO_SHORT");
  for (let i = 0; i < MAGIC.length; i++) {
    if (file[i] !== MAGIC[i]) throw new Error("BAD_MAGIC");
  }
  if (file[5] !== VERSION) throw new Error("BAD_VERSION");
  if (file[6] !== 0x01) throw new Error("BAD_KDF");
  if (file[7] !== 0x01) throw new Error("BAD_CIPHER");
  return {
    version: file[5],
    kdf: "Argon2id",
    cipher: "AES-256-GCM ×2 (cascade)",
    params: {
      memoryKiB: readU32(file, 8),
      iterations: readU32(file, 12),
      parallelism: file[16],
    },
    bodyLength: readU32(file, 74),
    totalLength: file.length,
    salt: file.slice(18, 50),
  };
}

export async function open(
  file: Uint8Array,
  password: string,
): Promise<{ payload: Payload; meta: SealedMeta }> {
  const meta = inspect(file);
  const header = file.slice(0, HEADER_LEN);
  const nonceA = file.slice(50, 62);
  const nonceB = file.slice(62, 74);
  const body = file.slice(HEADER_LEN);

  const { kOuter, kInner } = await deriveKeys(password, meta.salt, meta.params);

  let inner: Uint8Array;
  try {
    inner = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonceA as BufferSource, additionalData: header as BufferSource, tagLength: 128 },
        kOuter,
        body as BufferSource,
      ),
    );
  } catch {
    throw new Error("AUTH_FAILED");
  }

  let plain: Uint8Array;
  try {
    plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: nonceB as BufferSource, additionalData: header as BufferSource, tagLength: 128 },
        kInner,
        inner as BufferSource,
      ),
    );
  } catch {
    throw new Error("AUTH_FAILED");
  }

  const json = dec.decode(unpad(plain));
  plain.fill(0);
  const payload = JSON.parse(json) as Payload;
  if (typeof payload.msg !== "string") throw new Error("PAYLOAD_CORRUPT");
  return { payload, meta };
}

/* ------------------------------------------------------------------ */
/* armor (base64 text form, for pasting into chats / pastebins)        */
/* ------------------------------------------------------------------ */

export function toBase64(b: Uint8Array): string {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) {
    s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

export function fromBase64(s: string): Uint8Array {
  const bin = atob(s.replace(/\s+/g, ""));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const ARMOR_HEAD = "-----BEGIN CRYPT MESSAGE-----";
const ARMOR_TAIL = "-----END CRYPT MESSAGE-----";

export function armor(bytes: Uint8Array): string {
  const b64 = toBase64(bytes).replace(/(.{72})/g, "$1\n");
  return `${ARMOR_HEAD}\n${b64}\n${ARMOR_TAIL}`;
}

export function dearmor(text: string): Uint8Array {
  const t = text.trim();
  if (t.includes(ARMOR_HEAD)) {
    const body = t.split(ARMOR_HEAD)[1].split(ARMOR_TAIL)[0];
    return fromBase64(body);
  }
  return fromBase64(t);
}

/* ------------------------------------------------------------------ */
/* passphrase tooling                                                  */
/* ------------------------------------------------------------------ */

const WORDS = [
  "anchor","basalt","cipher","dagger","ember","falcon","glacier","harbor","ingot","jackal",
  "kestrel","lantern","monsoon","nomad","obsidian","pylon","quartz","raven","sable","tundra",
  "umbra","vector","warden","xenon","yonder","zephyr","bastion","crimson","drifter","echelon",
  "fathom","granite","hollow","iodine","juniper","kilo","lumen","mercury","nebula","onyx",
  "phantom","quiver","riptide","sentry","talon","upshot","vellum","wraith","yield","zodiac",
];

export function generatePassphrase(words = 6): string {
  const idx = new Uint32Array(words);
  crypto.getRandomValues(idx);
  return Array.from(idx, (n) => WORDS[n % WORDS.length]).join("-");
}

export interface Strength {
  bits: number;
  label: string;
  color: string;
  pct: number;
}

/** Rough entropy estimate of a passphrase (charset model + repetition penalty). */
export function estimateStrength(pw: string): Strength {
  if (!pw) return { bits: 0, label: "EMPTY", color: "bg-zinc-700", pct: 0 };
  let space = 0;
  if (/[a-z]/.test(pw)) space += 26;
  if (/[A-Z]/.test(pw)) space += 26;
  if (/[0-9]/.test(pw)) space += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) space += 33;
  const unique = new Set(pw).size;
  const effLen = pw.length * Math.min(1, 0.35 + unique / Math.max(pw.length, 1) * 0.65);
  const bits = Math.round(effLen * Math.log2(Math.max(space, 2)));

  let label = "CRITICAL", color = "bg-red-500";
  if (bits >= 60) { label = "WEAK"; color = "bg-orange-500"; }
  if (bits >= 80) { label = "ADEQUATE"; color = "bg-yellow-400"; }
  if (bits >= 110) { label = "STRONG"; color = "bg-emerald-400"; }
  if (bits >= 150) { label = "OVERKILL"; color = "bg-cyan-400"; }
  return { bits, label, color, pct: Math.min(100, (bits / 180) * 100) };
}

/**
 * Time to brute force, given the KDF cost. Assumes an adversary with 10,000
 * parallel cores, each able to run the Argon2id instance at `costSeconds`.
 */
export function crackTime(bits: number, p: KdfParams): string {
  if (bits <= 0) return "instant";
  // crude model: cost scales with memory * passes
  const costSeconds = (p.memoryKiB / 65536) * (p.iterations / 3) * 0.9;
  const cores = 10000;
  const guesses = Math.pow(2, bits - 1);
  const seconds = (guesses * costSeconds) / cores;
  return humanTime(seconds);
}

export function humanTime(seconds: number): string {
  const units: [number, string][] = [
    [1, "seconds"],
    [60, "minutes"],
    [3600, "hours"],
    [86400, "days"],
    [31557600, "years"],
    [31557600e3, "millennia"],
    [31557600e6, "million years"],
    [31557600e9, "billion years"],
  ];
  if (seconds < 1) return "< 1 second";
  let chosen = units[0];
  for (const u of units) if (seconds >= u[0]) chosen = u;
  const v = seconds / chosen[0];
  if (v > 1e6) return `${v.toExponential(2)} ${chosen[1]}`;
  return `${v.toLocaleString(undefined, { maximumFractionDigits: 1 })} ${chosen[1]}`;
}
