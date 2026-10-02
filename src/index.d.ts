export type Category = "prompt_injection" | "prompt_leak" | "secret" | "pii" | "off_topic" | "size" | string;

export interface Policy {
  blockAt?: number;
  ignoreCategories?: Category[];
  topics?: string[] | null;
  maxInputChars?: number;
  redactWith?: string;
  scanVariants?: boolean;
}

export interface Finding {
  id: string;
  category: Category;
  severity: number;
  reason: string;
  snippet: string;
  via?: string;
}

export interface Verdict {
  allowed: boolean;
  severity: number;
  findings: Finding[];
  categories: Category[];
  needsJudge: boolean;
  redacted?: string;
}

export interface Guard {
  checkInput(text: string): Verdict;
  checkOutput(text: string): Verdict & { redacted: string };
  policy: Required<Policy>;
}

export function createGuard(policy?: Policy): Guard;
