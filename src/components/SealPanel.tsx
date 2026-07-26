import { useMemo, useState } from "react";
import {
  PROFILES,
  armor,
  crackTime,
  estimateStrength,
  generatePassphrase,
  type ProfileId,
  type SealedMeta,
} from "../lib/crypt";
import { sealAsync } from "../lib/client";
import { Button, Input, Label, Panel, Stat, TextArea } from "./ui";
import { cn } from "../utils/cn";

function hexdump(b: Uint8Array, rows = 4): string {
  const out: string[] = [];
  for (let r = 0; r < rows; r++) {
    const slice = b.subarray(r * 16, r * 16 + 16);
    if (!slice.length) break;
    const hex = Array.from(slice, (x) => x.toString(16).padStart(2, "0")).join(" ");
    const ascii = Array.from(slice, (x) =>
      x >= 32 && x < 127 ? String.fromCharCode(x) : ".",
    ).join("");
    out.push(
      `${(r * 16).toString(16).padStart(4, "0")}  ${hex.padEnd(47)}  ${ascii}`,
    );
  }
  return out.join("\n");
}

interface Sealed {
  bytes: Uint8Array;
  meta: SealedMeta;
  ms: number;
  filename: string;
}

export default function SealPanel() {
  const [message, setMessage] = useState("");
  const [identity, setIdentity] = useState("");
  const [note, setNote] = useState("");
  const [password, setPassword] = useState("");
  const [reveal, setReveal] = useState(false);
  const [profile, setProfile] = useState<ProfileId>("hardened");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<Sealed | null>(null);
  const [copied, setCopied] = useState("");

  const p = PROFILES[profile];
  const strength = useMemo(() => estimateStrength(password), [password]);
  const eta = useMemo(() => crackTime(strength.bits, p), [strength.bits, p]);

  const ready = message.trim().length > 0 && password.length >= 8 && !busy;

  async function doSeal() {
    setError("");
    setBusy(true);
    setResult(null);
    try {
      const r = await sealAsync(
        {
          from: identity.trim() || "ANONYMOUS",
          msg: message,
          ts: Date.now(),
          note: note.trim() || undefined,
        },
        password,
        { memoryKiB: p.memoryKiB, iterations: p.iterations, parallelism: p.parallelism },
      );
      const stamp = new Date().toISOString().replace(/[-:]/g, "").slice(0, 15);
      setResult({
        bytes: r.bytes,
        meta: r.meta,
        ms: r.ms,
        filename: `msg_${stamp}.crypt`,
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "SEAL_FAILED");
    } finally {
      setBusy(false);
    }
  }

  function download() {
    if (!result) return;
    const blob = new Blob([result.bytes as BlobPart], {
      type: "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = result.filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  async function copy(what: "armor" | "pass") {
    if (what === "armor" && result) {
      await navigator.clipboard.writeText(armor(result.bytes));
    } else if (what === "pass") {
      await navigator.clipboard.writeText(password);
    }
    setCopied(what);
    setTimeout(() => setCopied(""), 1600);
  }

  function wipe() {
    setMessage("");
    setIdentity("");
    setNote("");
    setPassword("");
    setResult(null);
    setError("");
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[1.35fr_1fr]">
      <Panel
        title="COMPOSE // PLAINTEXT"
        tag={
          <span className="text-[10px] text-zinc-600">
            never leaves this device
          </span>
        }
      >
        <div className="space-y-4">
          <div>
            <Label hint={`${message.length} chars`}>MESSAGE BODY</Label>
            <TextArea
              rows={9}
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              placeholder="Type the message you need to disappear into noise…"
            />
          </div>

          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <Label hint="encrypted with the body">SIGNATURE / IDENTITY</Label>
              <Input
                value={identity}
                onChange={(e) => setIdentity(e.target.value)}
                placeholder="e.g. NIGHTJAR-07"
                maxLength={64}
              />
            </div>
            <div>
              <Label hint="optional">HANDLING NOTE</Label>
              <Input
                value={note}
                onChange={(e) => setNote(e.target.value)}
                placeholder="e.g. destroy after reading"
                maxLength={120}
              />
            </div>
          </div>

          <div>
            <Label hint="min 8 chars · 6+ words recommended">PASSPHRASE</Label>
            <div className="flex gap-2">
              <Input
                type={reveal ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••••••••••"
                autoComplete="new-password"
              />
              <Button variant="ghost" onClick={() => setReveal(!reveal)} title="reveal">
                {reveal ? "HIDE" : "SHOW"}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setPassword(generatePassphrase(6));
                  setReveal(true);
                }}
                title="generate a 6-word passphrase"
              >
                GEN
              </Button>
            </div>

            <div className="mt-3 space-y-2">
              <div className="h-1.5 w-full overflow-hidden bg-zinc-900">
                <div
                  className={cn("h-full transition-all duration-500", strength.color)}
                  style={{ width: `${strength.pct}%` }}
                />
              </div>
              <div className="flex flex-wrap items-center justify-between gap-2 text-[10px]">
                <span className="tracking-[0.2em] text-zinc-500">
                  ENTROPY ≈ <span className="text-emerald-400">{strength.bits} bits</span>{" "}
                  · {strength.label}
                </span>
                {password && (
                  <button
                    onClick={() => copy("pass")}
                    className="tracking-[0.2em] text-emerald-700 hover:text-emerald-400"
                  >
                    {copied === "pass" ? "COPIED ✓" : "COPY KEY"}
                  </button>
                )}
              </div>
              <p className="text-[10px] leading-relaxed text-zinc-600">
                Offline attack at 10,000 cores under the{" "}
                <span className="text-emerald-600">{p.name}</span> profile:{" "}
                <span className="text-emerald-300">{eta}</span>
              </p>
            </div>
          </div>
        </div>
      </Panel>

      <div className="space-y-5">
        <Panel title="KDF HARDNESS PROFILE">
          <div className="space-y-2">
            {(Object.keys(PROFILES) as ProfileId[]).map((id) => {
              const pr = PROFILES[id];
              const active = id === profile;
              return (
                <button
                  key={id}
                  onClick={() => setProfile(id)}
                  className={cn(
                    "w-full border px-3 py-2.5 text-left transition",
                    active
                      ? "border-emerald-500/70 bg-emerald-500/10 shadow-[0_0_25px_-12px_rgba(16,185,129,0.9)]"
                      : "border-emerald-950 hover:border-emerald-800",
                  )}
                >
                  <div className="flex items-center justify-between">
                    <span
                      className={cn(
                        "text-[11px] tracking-[0.28em]",
                        active ? "text-emerald-300 glow" : "text-zinc-500",
                      )}
                    >
                      {pr.name}
                    </span>
                    <span className="text-[10px] text-zinc-600">{pr.approxTime}</span>
                  </div>
                  <p className="mt-1 text-[10px] leading-relaxed text-zinc-600">
                    {pr.blurb}
                  </p>
                </button>
              );
            })}
          </div>
        </Panel>

        <Panel title="SEAL">
          <div className="space-y-3">
            <Button className="w-full" onClick={doSeal} disabled={!ready}>
              {busy ? "DERIVING KEY…" : "ENCRYPT & SEAL .CRYPT"}
            </Button>
            {busy && (
              <div className="relative h-1 overflow-hidden bg-zinc-900">
                <div className="sweep absolute inset-y-0 w-1/4 bg-emerald-400/80" />
              </div>
            )}
            {busy && (
              <p className="text-[10px] leading-relaxed text-emerald-700">
                argon2id · {(p.memoryKiB / 1024) | 0} MiB memory hard · {p.iterations}{" "}
                passes · ml-kem-1024 encapsulation … this delay is the entire point.
              </p>
            )}
            {!ready && !busy && (
              <p className="text-[10px] text-zinc-600">
                Requires a message body and a passphrase of 8+ characters.
              </p>
            )}
            {error && (
              <p className="border border-red-900/60 bg-red-950/30 p-2 text-[10px] text-red-400">
                ERROR :: {error}
              </p>
            )}
            <button
              onClick={wipe}
              className="w-full text-[10px] tracking-[0.25em] text-zinc-700 hover:text-red-400"
            >
              WIPE WORKSPACE
            </button>
          </div>
        </Panel>
      </div>

      {result && (
        <Panel
          className="lg:col-span-2"
          title="ARTIFACT READY"
          tag={
            <span className="text-[10px] text-emerald-500">
              sealed in {(result.ms / 1000).toFixed(2)}s
            </span>
          }
        >
          <div className="grid gap-5 md:grid-cols-2">
            <div>
              <div className="mb-3 flex items-center gap-3 border border-emerald-900/60 bg-black/50 px-3 py-3">
                <span className="text-2xl">🗝️</span>
                <div className="min-w-0">
                  <p className="truncate text-sm text-emerald-200">{result.filename}</p>
                  <p className="text-[10px] text-zinc-600">
                    {result.bytes.length.toLocaleString()} bytes · opaque binary
                  </p>
                </div>
              </div>
              <div className="flex flex-wrap gap-2">
                <Button onClick={download}>DOWNLOAD .CRYPT</Button>
                <Button variant="ghost" onClick={() => copy("armor")}>
                  {copied === "armor" ? "COPIED ✓" : "COPY AS TEXT"}
                </Button>
              </div>
              <p className="mt-3 text-[10px] leading-relaxed text-zinc-600">
                Ship the file anywhere — email, USB, pastebin, a photo-sharing forum.
                It contains no plaintext metadata: no sender, no subject, no length.
                Deliver the passphrase through a{" "}
                <span className="text-emerald-600">different channel</span>.
              </p>
            </div>

            <div>
              <div className="mb-2">
                <Stat k="FORMAT" v={`CRYPT v${result.meta.version}`} accent />
                <Stat k="KDF" v={result.meta.kdf} />
                <Stat
                  k="MEMORY COST"
                  v={`${(result.meta.params.memoryKiB / 1024) | 0} MiB`}
                />
                <Stat k="PASSES" v={result.meta.params.iterations} />
                <Stat k="KEM" v={result.meta.kem} accent />
                <Stat k="CIPHER" v={result.meta.cipher} />
                <Stat k="PADDED BODY" v={`${result.meta.bodyLength} B`} />
              </div>
              <pre className="overflow-x-auto border border-emerald-950 bg-black/70 p-3 text-[10px] leading-relaxed text-emerald-700">
{hexdump(result.bytes)}
{"\n…"}
              </pre>
            </div>
          </div>
        </Panel>
      )}
    </div>
  );
}
