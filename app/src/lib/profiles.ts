import { createSignal } from "solid-js";
import { invoke } from "@tauri-apps/api/core";
import type { FirewallMode } from "./rules";

export interface NetworkIdentity {
  key: string;
  label: string;
}
export interface Profile {
  name: string;
  networks: NetworkIdentity[];
  mode?: FirewallMode;
}
export interface ProfileState {
  profiles: Profile[];
  manual: string | null;
  active: string | null;
  network: NetworkIdentity | null;
  mode: FirewallMode;
}

const [profileState, setProfileState] = createSignal<ProfileState>();
export { profileState };

export const activeProfile = () => profileState()?.active ?? null;

export async function refreshProfiles(): Promise<void> {
  try {
    setProfileState(await invoke<ProfileState>("get_profiles"));
  } catch {
    /* engine offline */
  }
}

// privileged like a rule change: switching profile changes what is enforced
export async function saveProfiles(profiles: Profile[], manual: string | null): Promise<void> {
  try {
    await invoke("set_profiles", { profiles, manual });
  } finally {
    await refreshProfiles();
  }
}

/// the profile list with the current network added to `name`, and taken off
/// any other profile so one network never matches two
export function withNetwork(profiles: Profile[], name: string, network: NetworkIdentity): Profile[] {
  return profiles.map((profile) => {
    const networks = profile.networks.filter((known) => known.key !== network.key);
    return profile.name === name ? { ...profile, networks: [...networks, network] } : { ...profile, networks };
  });
}
