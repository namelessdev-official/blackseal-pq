import { Panel } from "./ui";

const FIELDS: [string, string, string][] = [
  ["0x00", "5 B", 'magic "CRYPT"'],
  ["0x05", "1 B", "format version (0x02)"],
  ["0x06", "1 B", "KDF id — 0x01 Argon2id → HKDF-SHA-512"],
  ["0x07", "1 B", "cipher id — 0x02 ML-KEM-1024 + AES-256-GCM cascade"],
  ["0x08", "4 B", "memory cost, KiB (uint32 LE)"],
  ["0x0C", "4 B", "iterations (uint32 LE)"],
  ["0x10", "1 B", "parallelism"],
  ["0x11", "1 B", "flags (reserved)"],
  ["0x12", "32 B", "salt (CSPRNG)"],
  ["0x32", "12 B", "nonce A — outer layer"],
  ["0x3E", "12 B", "nonce B — inner layer"],
  ["0x4A", "4 B", "body length (uint32 LE)"],
  ["0x4E", "1568 B", "ML-KEM-1024 encapsulation ciphertext"],
  ["0x66E", "n B", "ciphertext ‖ GCM tags"],
];

export default function SpecPanel() {
  return (
    <div className="grid gap-5 lg:grid-cols-2">
      <Panel title="CONTAINER SPEC // .CRYPT v2 — POST-QUANTUM">
        <div className="overflow-x-auto">
          <table className="w-full text-[11px]">
            <thead>
              <tr className="text-[10px] tracking-[0.2em] text-zinc-600">
                <th className="py-1 text-left font-normal">OFF</th>
                <th className="py-1 text-left font-normal">LEN</th>
                <th className="py-1 text-left font-normal">FIELD</th>
              </tr>
            </thead>
            <tbody>
              {FIELDS.map(([o, l, d]) => (
                <tr key={o} className="border-t border-dashed border-emerald-950">
                  <td className="py-1.5 pr-3 text-emerald-500">{o}</td>
                  <td className="py-1.5 pr-3 text-zinc-500">{l}</td>
                  <td className="py-1.5 text-zinc-400">{d}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-[10px] leading-relaxed text-zinc-600">
          The entire 1646-byte header — including the ML-KEM-1024 encapsulation —
          is fed to both AES-GCM layers as additional authenticated data.
          Downgrading the cost parameters, swapping salts, replacing the KEM
          ciphertext or splicing two containers together produces an
          authentication failure rather than a decryptable file. Legacy v1
          (pre-quantum) containers remain readable.
        </p>
      </Panel>

      <Panel title="CRYPTOGRAPHIC PIPELINE">
        <ol className="space-y-3 text-[11px] leading-relaxed text-zinc-400">
          {[
            "32 bytes of CSPRNG salt + two 96-bit nonces are drawn per message. No value is ever reused.",
            "Argon2id stretches the passphrase into 96 bytes of key material, burning up to 768 MiB of RAM per guess — memory-hardness is what kills GPU and ASIC cracking rigs.",
            "64 of those bytes deterministically seed an ML-KEM-1024 keypair (FIPS 203, NIST security level 5). A fresh lattice encapsulation per message yields a 32-byte shared secret that no known quantum algorithm — Shor's included — can recover.",
            "HKDF-SHA-512 mixes the remaining 32-byte password share with the ML-KEM shared secret into two independent AES-256 keys. Breaking the container requires beating BOTH Argon2id and Module-LWE.",
            "Payload {identity, message, timestamp, note} is serialised, prefixed with its true length, then padded with random bytes to a 512-byte boundary so file size leaks nothing.",
            "Inner AES-256-GCM encrypts the padded payload. Outer AES-256-GCM encrypts the resulting ciphertext. Two independent 128-bit tags must both verify. AES-256 itself keeps ≥128-bit strength even against Grover's quantum search.",
            "All work happens in a web worker in your browser — pure WASM + JS, no native code. No network calls, no telemetry, no accounts, no server-side logs.",
          ].map((t, i) => (
            <li key={i} className="flex gap-3">
              <span className="mt-0.5 shrink-0 text-emerald-600">
                {String(i + 1).padStart(2, "0")}
              </span>
              <span>{t}</span>
            </li>
          ))}
        </ol>
      </Panel>

      <Panel title="OPERATIONAL SECURITY" className="lg:col-span-2">
        <div className="grid gap-4 md:grid-cols-3">
          {[
            [
              "SPLIT YOUR CHANNELS",
              "Never send the container and the passphrase over the same medium. File over email, key over voice — or pre-shared, in person.",
            ],
            [
              "THE KEY IS THE WEAK LINK",
              "ML-KEM-1024 and AES-256 will not be broken — not even by a quantum computer. Your passphrase will. Use the generator: six random words ≈ 110+ bits, which no cost model in this century defeats.",
            ],
            [
              "HARVEST NOW, DECRYPT NEVER",
              "Adversaries recording ciphertext today to decrypt once quantum hardware arrives get nothing: the key schedule is bound to Module-LWE, a problem with no known quantum speedup.",
            ],
            [
              "CONTAINERS ARE ANONYMOUS",
              "A .crypt file has no sender field, no subject, no recipient and a padded length. It is indistinguishable from random bytes past the 7-byte header.",
            ],
            [
              "DENIABLE DISTRIBUTION",
              "Post it publicly — a forum attachment, a gist, an image board. Broadcasting to everyone hides who the intended reader is.",
            ],
            [
              "ROTATE PASSPHRASES",
              "One passphrase per message, or per contact per week. A compromised key should never unlock your archive.",
            ],
            [
              "NO RECOVERY EXISTS",
              "There is no reset, no backdoor, no escrow. Lose the passphrase and the plaintext is gone — that is the guarantee, not a bug.",
            ],
          ].map(([h, b]) => (
            <div key={h} className="border border-emerald-950 bg-black/40 p-3">
              <p className="mb-1.5 text-[10px] tracking-[0.22em] text-emerald-400">
                {h}
              </p>
              <p className="text-[11px] leading-relaxed text-zinc-500">{b}</p>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}
