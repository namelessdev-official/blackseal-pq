import { useRef, useState } from "react";
import { dearmor, inspect, type Payload, type SealedMeta } from "../lib/crypt";
import { openAsync } from "../lib/client";
import { Button, Input, Label, Panel, Stat, TextArea } from "./ui";
import { cn } from "../utils/cn";

const ERRORS: Record<string, string> = {
  AUTH_FAILED:
    "AUTHENTICATION FAILED — wrong passphrase, or the file was altered in transit. There is no way to tell which.",
  BAD_MAGIC: "NOT A .CRYPT CONTAINER — magic bytes missing.",
  BAD_VERSION: "UNSUPPORTED CONTAINER VERSION.",
  BAD_KDF: "UNKNOWN KEY DERIVATION FUNCTION.",
  BAD_CIPHER: "UNKNOWN CIPHER SUITE.",
  TOO_SHORT: "TRUNCATED FILE — container is too small to be valid.",
  PADDING_CORRUPT: "PADDING CORRUPT — container damaged.",
  PAYLOAD_CORRUPT: "PAYLOAD CORRUPT — container damaged.",
};

export default function OpenPanel() {
  const [file, setFile] = useState<Uint8Array | null>(null);
  const [name, setName] = useState("");
  const [meta, setMeta] = useState<SealedMeta | null>(null);
  const [pasteMode, setPasteMode] = useState(false);
  const [pasted, setPasted] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [error, setError] = useState("");
  const [out, setOut] = useState<{ payload: Payload; ms: number } | null>(null);
  const [drag, setDrag] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  function load(bytes: Uint8Array, label: string) {
    setError("");
    setOut(null);
    setAttempts(0);
    try {
      setMeta(inspect(bytes));
      setFile(bytes);
      setName(label);
    } catch (e) {
      setFile(null);
      setMeta(null);
      const code = e instanceof Error ? e.message : "UNKNOWN";
      setError(ERRORS[code] ?? code);
    }
  }

  async function onFiles(files: FileList | null) {
    if (!files?.length) return;
    const f = files[0];
    const buf = new Uint8Array(await f.arrayBuffer());
    load(buf, f.name);
  }

  function loadPasted() {
    try {
      load(dearmor(pasted), "pasted-message.crypt");
    } catch {
      setError("Could not decode that text as an armored CRYPT block.");
    }
  }

  async function decrypt() {
    if (!file) return;
    setBusy(true);
    setError("");
    try {
      const r = await openAsync(file, password);
      setOut({ payload: r.payload, ms: r.ms });
    } catch (e) {
      const code = e instanceof Error ? e.message : "UNKNOWN";
      setError(ERRORS[code] ?? code);
      setAttempts((a) => a + 1);
    } finally {
      setBusy(false);
    }
  }

  function reset() {
    setFile(null);
    setMeta(null);
    setOut(null);
    setPassword("");
    setError("");
    setName("");
    setPasted("");
    setAttempts(0);
  }

  return (
    <div className="grid gap-5 lg:grid-cols-[1fr_1.35fr]">
      <div className="space-y-5">
        <Panel
          title="LOAD CONTAINER"
          tag={
            <button
              onClick={() => setPasteMode(!pasteMode)}
              className="text-[10px] tracking-[0.2em] text-emerald-700 hover:text-emerald-400"
            >
              {pasteMode ? "USE FILE" : "PASTE TEXT"}
            </button>
          }
        >
          {pasteMode ? (
            <div className="space-y-3">
              <Label hint="-----BEGIN CRYPT MESSAGE-----">ARMORED BLOCK</Label>
              <TextArea
                rows={7}
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                placeholder={"-----BEGIN CRYPT MESSAGE-----\nQ1JZUFQB…\n-----END CRYPT MESSAGE-----"}
                className="text-[11px]"
              />
              <Button className="w-full" onClick={loadPasted} disabled={!pasted.trim()}>
                PARSE BLOCK
              </Button>
            </div>
          ) : (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setDrag(true);
              }}
              onDragLeave={() => setDrag(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDrag(false);
                onFiles(e.dataTransfer.files);
              }}
              onClick={() => inputRef.current?.click()}
              className={cn(
                "cursor-pointer border border-dashed px-4 py-10 text-center transition",
                drag
                  ? "border-emerald-400 bg-emerald-500/10"
                  : "border-emerald-900/70 hover:border-emerald-700",
              )}
            >
              <div className="text-3xl">📁</div>
              <p className="mt-3 text-[11px] tracking-[0.2em] text-emerald-500/80">
                DROP A .CRYPT FILE
              </p>
              <p className="mt-1 text-[10px] text-zinc-600">or click to browse</p>
              <input
                ref={inputRef}
                type="file"
                accept=".crypt,application/octet-stream"
                className="hidden"
                onChange={(e) => onFiles(e.target.files)}
              />
            </div>
          )}

          {meta && (
            <div className="mt-4">
              <p className="mb-2 truncate text-[11px] text-emerald-300">▸ {name}</p>
              <Stat k="FORMAT" v={`CRYPT v${meta.version}`} accent />
              <Stat k="KDF" v={meta.kdf} />
              <Stat k="MEMORY COST" v={`${(meta.params.memoryKiB / 1024) | 0} MiB`} />
              <Stat k="PASSES" v={meta.params.iterations} />
              <Stat k="CIPHER" v={meta.cipher} />
              <Stat k="SIZE" v={`${meta.totalLength.toLocaleString()} B`} />
              <p className="mt-3 text-[10px] leading-relaxed text-zinc-600">
                Header exposes only cost parameters and random salt/nonces. Sender,
                length and timestamp remain sealed inside the ciphertext.
              </p>
            </div>
          )}
        </Panel>

        {meta && (
          <Panel title="UNSEAL">
            <div className="space-y-3">
              <Label>PASSPHRASE</Label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && !busy && decrypt()}
                placeholder="••••••••••••••••"
              />
              <Button className="w-full" onClick={decrypt} disabled={busy || !password}>
                {busy ? "DERIVING KEY…" : "DECRYPT"}
              </Button>
              {busy && (
                <div className="relative h-1 overflow-hidden bg-zinc-900">
                  <div className="sweep absolute inset-y-0 w-1/4 bg-emerald-400/80" />
                </div>
              )}
              {attempts > 0 && (
                <p className="text-[10px] text-zinc-600">
                  failed attempts this session: {attempts} · each one costs the same{" "}
                  {(meta.params.memoryKiB / 1024) | 0} MiB of work an attacker pays.
                </p>
              )}
              <button
                onClick={reset}
                className="w-full text-[10px] tracking-[0.25em] text-zinc-700 hover:text-red-400"
              >
                EJECT CONTAINER
              </button>
            </div>
          </Panel>
        )}
      </div>

      <div className="space-y-5">
        {error && (
          <Panel title="STATUS" className="border-red-900/70">
            <p className="text-[11px] leading-relaxed text-red-400">✖ {error}</p>
          </Panel>
        )}

        {out ? (
          <Panel
            title="DECRYPTED TRANSMISSION"
            tag={
              <span className="text-[10px] text-emerald-500">
                ✔ AUTHENTIC · {(out.ms / 1000).toFixed(2)}s
              </span>
            }
          >
            <div className="space-y-4">
              <div className="flex flex-wrap items-center gap-3 border border-emerald-900/60 bg-emerald-950/20 px-3 py-3">
                <div className="flex h-10 w-10 items-center justify-center border border-emerald-700/60 text-emerald-300">
                  {out.payload.from.slice(0, 2).toUpperCase()}
                </div>
                <div>
                  <p className="text-[10px] tracking-[0.25em] text-zinc-600">
                    SIGNED BY
                  </p>
                  <p className="text-sm text-emerald-200 glow">{out.payload.from}</p>
                </div>
                <div className="ml-auto text-right">
                  <p className="text-[10px] tracking-[0.25em] text-zinc-600">SEALED</p>
                  <p className="text-[11px] text-zinc-400">
                    {new Date(out.payload.ts).toLocaleString()}
                  </p>
                </div>
              </div>

              {out.payload.note && (
                <p className="border-l-2 border-amber-500/70 bg-amber-500/5 px-3 py-2 text-[11px] text-amber-300">
                  HANDLING :: {out.payload.note}
                </p>
              )}

              <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap border border-emerald-900/50 bg-black/60 p-4 text-sm leading-relaxed text-emerald-50">
{out.payload.msg}
              </pre>

              <div className="flex flex-wrap gap-2">
                <Button
                  variant="ghost"
                  onClick={() => navigator.clipboard.writeText(out.payload.msg)}
                >
                  COPY MESSAGE
                </Button>
                <Button variant="danger" onClick={reset}>
                  BURN FROM SCREEN
                </Button>
              </div>

              <p className="text-[10px] leading-relaxed text-zinc-600">
                Integrity verified by two independent AES-GCM tags bound to the
                container header — the sender identity and cost parameters cannot have
                been tampered with.
              </p>
            </div>
          </Panel>
        ) : (
          !error && (
            <Panel title="AWAITING CONTAINER">
              <div className="space-y-3 py-6 text-center">
                <p className="text-4xl opacity-30">🛰️</p>
                <p className="text-[11px] tracking-[0.2em] text-zinc-600">
                  NO TRANSMISSION LOADED
                </p>
                <p className="mx-auto max-w-sm text-[10px] leading-relaxed text-zinc-700">
                  Decryption happens entirely in this browser tab, inside a web worker.
                  Nothing is uploaded, logged, or transmitted — there is no server to
                  subpoena.
                </p>
              </div>
            </Panel>
          )
        )}
      </div>
    </div>
  );
}
