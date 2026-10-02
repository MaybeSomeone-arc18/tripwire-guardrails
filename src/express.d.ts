import type { Guard, Verdict } from "./index.js";
import type { Judge } from "./judge.js";

export interface TripwireOptions {
  field?: string;
  getText?(req: any): unknown;
  outputField?: string;
  guardOutput?: boolean;
  judge?: Judge;
  always?: boolean;
  fallback?: string;
  onBlock?(req: any, res: any, verdict: Partial<Verdict>): void;
}
export function tripwire(guard: Guard, opts?: TripwireOptions): (req: any, res: any, next: (err?: unknown) => void) => Promise<void>;
