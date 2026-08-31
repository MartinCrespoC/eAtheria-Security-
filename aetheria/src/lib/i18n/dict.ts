import en from "./en";
import es from "./es";
import type { Dictionary } from "./en";
import { DEFAULT_LOCALE, type Locale } from "./types";

export const DICTIONARIES: Record<Locale, Dictionary> = { en, es };

/**
 * Resolve a dot-path ("landing.hero.titleA") against a dictionary,
 * falling back to English when the key is missing in the active locale.
 */
export function resolveKey(dict: Dictionary, path: string): unknown {
  let node: unknown = dict;
  for (const part of path.split(".")) {
    if (node == null || typeof node !== "object") return undefined;
    node = (node as Record<string, unknown>)[part];
  }
  return node;
}

export function translate(locale: Locale, path: string): string {
  const dict = DICTIONARIES[locale] ?? DICTIONARIES[DEFAULT_LOCALE];
  const value = resolveKey(dict, path) ?? resolveKey(DICTIONARIES[DEFAULT_LOCALE], path);
  return typeof value === "string" ? value : path;
}

/** Same as translate but for array values (FAQ items, feature lists...) */
export function translateArray<T>(locale: Locale, path: string): T[] {
  const dict = DICTIONARIES[locale] ?? DICTIONARIES[DEFAULT_LOCALE];
  const value = resolveKey(dict, path) ?? resolveKey(DICTIONARIES[DEFAULT_LOCALE], path);
  return Array.isArray(value) ? (value as T[]) : [];
}
