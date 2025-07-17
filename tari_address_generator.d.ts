/* tslint:disable */
/* eslint-disable */
export function init(): void;
export function decode_tari_address(address_str: string): any;
export function decode_tari_address_with_breakdown(address_str: string): any;
export function init_panic_hook(): void;
export class WasmTariAddress {
  private constructor();
  free(): void;
  /**
   * Get the address in Base58 format
   */
  to_base58(): string;
  /**
   * Get the address in emoji format
   */
  to_emoji(): string;
  /**
   * Get the network as a string
   */
  network(): string;
  /**
   * Check if the address has a payment ID
   */
  has_payment_id(): boolean;
  /**
   * Get the payment ID if present
   */
  payment_id(): Uint8Array | undefined;
}
export class WasmTariAddressGenerator {
  free(): void;
  constructor();
  /**
   * Generate a new wallet for the specified network
   */
  generate_new_wallet(network: string): WasmTariWallet;
  /**
   * Restore a wallet from a seed phrase
   */
  restore_from_seed_phrase(seed_phrase: string, network: string): WasmTariWallet;
  /**
   * Parse an address from string (auto-detects format)
   */
  parse_address(address: string): WasmTariAddress;
  /**
   * Validate a seed phrase
   */
  validate_seed_phrase(seed_phrase: string): boolean;
}
export class WasmTariWallet {
  private constructor();
  free(): void;
  /**
   * Get the address in Base58 format
   */
  address_base58(): string;
  /**
   * Get the address in emoji format
   */
  address_emoji(): string;
  /**
   * Get the seed phrase
   */
  seed_phrase(): string;
  /**
   * Get the network as a string
   */
  network(): string;
  new_address_with_payment_id(payment_id: string): WasmTariAddress;
  /**
   * Get the view private key as hex string
   */
  view_private_key_hex(): string;
  /**
   * Get the spend private key as hex string
   */
  spend_private_key_hex(): string;
  /**
   * Get the view public key as hex string
   */
  view_public_key_hex(): string;
  /**
   * Get the spend public key as hex string
   */
  spend_public_key_hex(): string;
}

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
  readonly memory: WebAssembly.Memory;
  readonly __wbg_wasmtariaddressgenerator_free: (a: number, b: number) => void;
  readonly wasmtariaddressgenerator_new: () => [number, number, number];
  readonly wasmtariaddressgenerator_generate_new_wallet: (a: number, b: number, c: number) => [number, number, number];
  readonly wasmtariaddressgenerator_restore_from_seed_phrase: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
  readonly wasmtariaddressgenerator_parse_address: (a: number, b: number, c: number) => [number, number, number];
  readonly wasmtariaddressgenerator_validate_seed_phrase: (a: number, b: number, c: number) => number;
  readonly __wbg_wasmtariwallet_free: (a: number, b: number) => void;
  readonly wasmtariwallet_address_base58: (a: number) => [number, number];
  readonly wasmtariwallet_address_emoji: (a: number) => [number, number];
  readonly wasmtariwallet_seed_phrase: (a: number) => [number, number];
  readonly wasmtariwallet_network: (a: number) => [number, number];
  readonly wasmtariwallet_new_address_with_payment_id: (a: number, b: number, c: number) => [number, number, number];
  readonly wasmtariwallet_view_private_key_hex: (a: number) => [number, number];
  readonly wasmtariwallet_spend_private_key_hex: (a: number) => [number, number];
  readonly wasmtariwallet_view_public_key_hex: (a: number) => [number, number];
  readonly wasmtariwallet_spend_public_key_hex: (a: number) => [number, number];
  readonly __wbg_wasmtariaddress_free: (a: number, b: number) => void;
  readonly wasmtariaddress_to_base58: (a: number) => [number, number];
  readonly wasmtariaddress_to_emoji: (a: number) => [number, number];
  readonly wasmtariaddress_network: (a: number) => [number, number];
  readonly wasmtariaddress_has_payment_id: (a: number) => number;
  readonly wasmtariaddress_payment_id: (a: number) => [number, number];
  readonly decode_tari_address: (a: number, b: number) => [number, number, number];
  readonly decode_tari_address_with_breakdown: (a: number, b: number) => [number, number, number];
  readonly init_panic_hook: () => void;
  readonly init: () => void;
  readonly __wbindgen_malloc: (a: number, b: number) => number;
  readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
  readonly __wbindgen_exn_store: (a: number) => void;
  readonly __externref_table_alloc: () => number;
  readonly __wbindgen_export_4: WebAssembly.Table;
  readonly __wbindgen_free: (a: number, b: number, c: number) => void;
  readonly __externref_table_dealloc: (a: number) => void;
  readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;
/**
* Instantiates the given `module`, which can either be bytes or
* a precompiled `WebAssembly.Module`.
*
* @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
*
* @returns {InitOutput}
*/
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
* If `module_or_path` is {RequestInfo} or {URL}, makes a request and
* for everything else, calls `WebAssembly.instantiate` directly.
*
* @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
*
* @returns {Promise<InitOutput>}
*/
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
