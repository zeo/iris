import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import { refreshRules, type Rule } from "./rules";

// a rule a plugin suggested. nothing is enforced until the user accepts, which
// runs elevated exactly like adding the rule by hand.
export interface RuleProposal {
  id: number;
  source: string;
  rule: Rule;
  reason: string;
  at_ms: number;
  state: "pending" | "accepted" | "rejected";
}

const [proposals, setProposals] = createSignal<RuleProposal[]>([]);
export { proposals };

export const pendingProposals = () => proposals().filter((p) => p.state === "pending");

export async function refreshProposals(): Promise<void> {
  try {
    setProposals(await invoke<RuleProposal[]>("list_proposals"));
  } catch {
    /* engine offline */
  }
}

// a live push while the window is open; the engine dedupes, so replace by id
export function upsertProposal(p: RuleProposal): void {
  setProposals((list) => [p, ...list.filter((x) => x.id !== p.id)]);
}

export async function acceptProposal(id: number): Promise<void> {
  await invoke("proposal_accept", { id });
  await Promise.all([refreshProposals(), refreshRules()]);
}

export async function rejectProposal(id: number): Promise<void> {
  await invoke("reject_proposal", { id });
  await refreshProposals();
}
