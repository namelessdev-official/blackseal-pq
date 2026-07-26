/// <reference lib="webworker" />
import { seal, open, type KdfParams, type Payload } from "./crypt";

type Req =
  | { id: number; op: "seal"; payload: Payload; password: string; params: KdfParams }
  | { id: number; op: "open"; file: Uint8Array; password: string };

self.onmessage = async (e: MessageEvent<Req>) => {
  const req = e.data;
  const t0 = performance.now();
  try {
    if (req.op === "seal") {
      const r = await seal(req.payload, req.password, req.params);
      (self as unknown as Worker).postMessage({
        id: req.id,
        ok: true,
        bytes: r.bytes,
        meta: r.meta,
        ms: performance.now() - t0,
      });
    } else {
      const r = await open(req.file, req.password);
      (self as unknown as Worker).postMessage({
        id: req.id,
        ok: true,
        payload: r.payload,
        meta: r.meta,
        ms: performance.now() - t0,
      });
    }
  } catch (err) {
    (self as unknown as Worker).postMessage({
      id: req.id,
      ok: false,
      error: err instanceof Error ? err.message : String(err),
      ms: performance.now() - t0,
    });
  }
};
