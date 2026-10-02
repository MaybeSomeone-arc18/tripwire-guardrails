import type { Guard, Verdict } from "./index.js";

export interface JudgeResult {
  verdict: "allow" | "block";
  category: string;
  reason: string;
  attempts?: number;
}

export interface JudgeOptions {
  apiKey?: string;
  model?: string;
  provider?: "gemini" | "ollama";
  endpoint?: string;
  timeoutMs?: number;
  retries?: number;
  backoffMs?: number;
}

export interface Judge {
  judge(text: string, opts?: { direction?: "input" | "output" }): Promise<JudgeResult>;
}

export function createJudge(opts?: JudgeOptions): Judge;
export function checkWithJudge(
  guard: Guard,
  judge: Judge,
  text: string,
  direction?: "input" | "output",
  opts?: { always?: boolean },
): Promise<Verdict & { judged: boolean; judge?: JudgeResult }>;
