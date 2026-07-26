import { useEffect, useState } from "react";
import SealPanel from "./components/SealPanel";
import OpenPanel from "./components/OpenPanel";
import SpecPanel from "./components/SpecPanel";
import { cn } from "./utils/cn";

type Tab = "seal" | "open" | "spec";

const TABS: [Tab, string][] = [
  ["seal", "SEAL MESSAGE"],
  ["open", "OPEN .CRYPT"],
  ["spec", "SPECIFICATION"],
];

function Clock() {
  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span className="tabular-nums">
      {now.toISOString().slice(11, 19)}Z
    </span>
  );
}

export default function App() {
  const [tab, setTab] = useState<Tab>("seal");
  const online = typeof navigator !== "undefined" ? navigator.onLine : true;

  return (
    <div className="tac-bg relative min-h-screen">
      <div className="relative z-10 mx-auto max-w-6xl px-4 py-6 md:px-6 md:py-10">
        {/* header */}
        <header className="mb-6 border border-emerald-900/60 bg-[#070b0c]/85 clip-corner">
          <div className="flex flex-wrap items-center gap-4 px-4 py-3 md:px-5">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center border border-emerald-600/70 text-emerald-400 glow">
                ✦
              </div>
              <div>
                <h1 className="text-sm tracking-[0.42em] text-emerald-300 glow flicker">
                  BLACKSEAL
                </h1>
                <p className="text-[10px] tracking-[0.24em] text-zinc-600">
                  POST-QUANTUM MESSAGE ENCRYPTION TERMINAL
                </p>
              </div>
            </div>

            <div className="ml-auto flex flex-wrap items-center gap-4 text-[10px] tracking-[0.2em] text-zinc-600">
              <span className="flex items-center gap-2">
                <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-400" />
                LOCAL-ONLY
              </span>
              <span className="hidden sm:inline">ML-KEM-1024 · ARGON2ID · AES-256-GCM×2</span>
              <span className={cn(online ? "text-zinc-600" : "text-emerald-400")}>
                {online ? "NET: UNUSED" : "NET: OFFLINE ✓"}
              </span>
              <Clock />
            </div>
          </div>

          <nav className="flex border-t border-emerald-900/50">
            {TABS.map(([id, label]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={cn(
                  "flex-1 px-3 py-2.5 text-[10px] tracking-[0.24em] transition md:flex-none md:px-7",
                  tab === id
                    ? "border-b-2 border-emerald-400 bg-emerald-500/10 text-emerald-300"
                    : "border-b-2 border-transparent text-zinc-600 hover:text-emerald-500",
                )}
              >
                {label}
              </button>
            ))}
          </nav>
        </header>

        {tab === "seal" && <SealPanel />}
        {tab === "open" && <OpenPanel />}
        {tab === "spec" && <SpecPanel />}

        <footer className="mt-8 flex flex-wrap items-center justify-between gap-3 border-t border-emerald-950 pt-4 text-[10px] tracking-[0.18em] text-zinc-700">
          <span>
            NO SERVER · NO ACCOUNTS · NO TELEMETRY · SOURCE RUNS ENTIRELY IN YOUR TAB
          </span>
          <span>
            SAVE THE PAGE AND RUN IT AIR-GAPPED — IT NEVER NEEDS A NETWORK
          </span>
        </footer>
      </div>
    </div>
  );
}
