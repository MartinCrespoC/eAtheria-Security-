/**
 * i18n Module — Barrel Export
 *
 * Centralizes internationalization exports:
 * - Language type
 * - Translation dictionary
 * - Translation function t()
 * - Help text getter
 */

export type { Language } from "./translations";
export { translations, t, getHelpText } from "./translations";
