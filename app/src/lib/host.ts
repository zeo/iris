import { invoke as call, opener } from "@ceri/app";

export { appWindow, listen } from "@ceri/app";

// the views show a failed command's message as it is
const plain = (error: unknown) => Promise.reject(error instanceof Error ? error.message : error);

export function invoke<T = unknown>(command: string, args?: unknown): Promise<T> {
  return call<T>(command, args).catch(plain);
}

export function openUrl(url: string): Promise<void> {
  return opener.openUrl(url).catch(plain);
}

export function revealItemInDir(path: string): Promise<void> {
  return opener.revealItemInDir(path).catch(plain);
}
