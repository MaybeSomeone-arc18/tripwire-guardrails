import type { Guard, Verdict } from "./index.js";

export interface StreamGuard {
  write(chunk: string): string;
  end(): string;
  readonly blocked: boolean;
  readonly verdict: Verdict | null;
}
export function createStreamGuard(guard: Guard, opts?: { holdBack?: number; fallback?: string }): StreamGuard;
