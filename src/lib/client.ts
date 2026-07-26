import CryptWorker from "./worker?worker&inline";
import {
  seal,
  open,
  type KdfParams,
  type Payload,
  type SealedMeta,
} from "./crypt";

let worker: Worker | null = null;
let workerBroken = false;
let seq = 0;

function getWorker(): Worker | null {
  if (workerBroken) return null;
  if (!worker) {
    try {
      const w = new CryptWorker();
      w.onerror = () => {
        workerBroken = true;
      };
      worker = w;
    } catch {
      workerBroken = true;
      return null;
    }
  }
  return worker;
}

function call<T>(msg: Record<string, unknown>): Promise<T & { ms: number }> | null {
  const w = getWorker();
  if (!w) return null;
  const id = ++seq;
  return new Promise((resolve, reject) => {
    const onMsg = (e: MessageEvent) => {
      if (e.data?.id !== id) return;
      cleanup();
      if (e.data.ok) resolve(e.data);
      else reject(new Error(e.data.error));
    };
    const onErr = () => {
      cleanup();
      workerBroken = true;
      reject(new Error("WORKER_FAILED"));
    };
    const cleanup = () => {
      w.removeEventListener("message", onMsg);
      w.removeEventListener("error", onErr);
    };
    w.addEventListener("message", onMsg);
    w.addEventListener("error", onErr);
    w.postMessage({ id, ...msg });
  });
}

/** Yield to the browser so spinners paint before a blocking main-thread KDF. */
const paint = () =>
  new Promise<void>((r) => requestAnimationFrame(() => setTimeout(r, 30)));

export async function sealAsync(
  payload: Payload,
  password: string,
  params: KdfParams,
): Promise<{ bytes: Uint8Array; meta: SealedMeta; ms: number }> {
  const viaWorker = call<{ bytes: Uint8Array; meta: SealedMeta }>({
    op: "seal",
    payload,
    password,
    params,
  });
  if (viaWorker) {
    try {
      return await viaWorker;
    } catch (e) {
      if ((e as Error).message !== "WORKER_FAILED") throw e;
    }
  }
  await paint();
  const t0 = performance.now();
  const r = await seal(payload, password, params);
  return { ...r, ms: performance.now() - t0 };
}

export async function openAsync(
  file: Uint8Array,
  password: string,
): Promise<{ payload: Payload; meta: SealedMeta; ms: number }> {
  const viaWorker = call<{ payload: Payload; meta: SealedMeta }>({
    op: "open",
    file,
    password,
  });
  if (viaWorker) {
    try {
      return await viaWorker;
    } catch (e) {
      if ((e as Error).message !== "WORKER_FAILED") throw e;
    }
  }
  await paint();
  const t0 = performance.now();
  const r = await open(file, password);
  return { ...r, ms: performance.now() - t0 };
}
