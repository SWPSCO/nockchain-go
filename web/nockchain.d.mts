/** uint64 values are canonical decimal strings; digests are Base58 strings. */
export type Uint64 = string;
/** Canonical JAM bytes encoded as hexadecimal. */
export type Jam = string;
export interface HeightRange { min?: Uint64 | null; max?: Uint64 | null }
export interface Timelock { relative: HeightRange; absolute: HeightRange }
export interface Condition { threshold?: number; keys?: string[]; timelock?: Timelock | null; hashes?: string[]; burn?: boolean }
export type Lock = Condition | { conditions: Condition[] } | { jam: Jam };
export interface NoteName { first: string; last: string }
/** Complete V0 or V1 record, or the explicit fields of a V1 record. */
export type Note = { jam: Jam } | (NoteName & { originPage: Uint64; noteDataJam: Jam; nicks: Uint64 });
export type Output = ({ lock: Lock } | { lockRoot: string }) & { noteDataJam?: Jam; nicks: Uint64 };
export interface Spend { note: Note; lock?: Lock; outputs: Output[]; fee: Uint64; leafNumber?: number; preimages?: Jam[] }
export interface FeeParameters { height?: Uint64; bythosPhase?: Uint64; baseFee?: Uint64; inputFeeDivisor?: Uint64; minFee?: Uint64 }
export interface FundPolicy { lockRoot: string; firstName: string; activationHeight: Uint64; minimum: Uint64 }
/** Supply complete V0 records in notes when parsing migration transactions. */
export interface TransactionContext { fees?: FeeParameters; fundPolicy?: FundPolicy; notes?: Note[] }
export type LockReview = { root: string; lockJam: Jam } & ({ threshold: number; keys: string[]; timelock: Timelock | null; timelocks: Timelock[]; hashes: string[]; burn: boolean } | { conditions: LockReview[] });
export interface MigrationLockReview { version: 0; root: string; threshold: number; publicKeys: string[] }
export interface OutputReview { lockRoot: string; nicks: Uint64; parentHash: string; noteDataJam: Jam; lock: LockReview | null }
export interface SpendReview extends NoteName { proofJam: Jam | null; lock: LockReview | MigrationLockReview; fee: Uint64; signatureHash: string; signedKeys: string[]; outputs: OutputReview[] }
export interface Review { id: string; feeNicks: Uint64; outputNicks: Uint64; minimumFeeNicks: Uint64; spends: SpendReview[] }
export interface Wire { jam: Jam; summary: Review }
export type Planning = {
 outputs: Output[]; refund: Output; sweep?: Output; selection?: NoteName[];
 order?: 'ascending' | 'descending'; feeNicks?: Uint64; version?: 0 | 1;
} & ({ signerPKH: string } | { lockRoot: string; lock?: Lock; leafNumber?: number; preimages?: Jam[] });
export interface PlanResult {
 transaction: Wire; selected: (NoteName & { jam: Jam })[]; selectedTotal: Uint64;
 outputs: { lockRoot: string; noteDataJam: Jam; nicks: Uint64 }[];
 refunds: (NoteName & { amount: Uint64 })[];
 finalFee: Uint64; minimumFee: Uint64; seedWords: Uint64; witnessWords: Uint64;
}
export interface API {
 call(method: 'receive', parameters: { zpub: string; index: number }): { index: number; address: string; lockRoot: string };
 call(method: 'derivePublic', parameters: { zpub: string; path: string }): { zpub: string; address: string; lockRoot: string };
 call(method: 'parseNocks', parameters: { amount: string }): Uint64;
 call(method: 'formatNocks', parameters: { nicks: Uint64 }): string;
 call(method: 'lock', parameters: { inputLocks: [Lock] }): LockReview & { first: string };
 call(method: 'minimumFee', parameters: TransactionContext & { inputLocks: Lock[]; outputLocks: Lock[] }): Uint64;
 call(method: 'plan', parameters: TransactionContext & { notes: Note[]; height?: Uint64; planning: Planning }): PlanResult;
 call(method: 'prepareTransaction', parameters: TransactionContext & { plans: Spend[] }): Wire;
 call(method: 'inspect', parameters: TransactionContext & { jam: Jam }): Review;
 call(method: 'verifySignatures', parameters: TransactionContext & { jam: Jam }): true;
 call(method: 'validateInputs', parameters: TransactionContext & { jam: Jam; notes: Note[]; height: Uint64 }): true;
 call(method: 'signTransaction', parameters: TransactionContext & { jam: Jam; key: string }): Wire;
 call(method: 'mergeSignatures', parameters: TransactionContext & { jam: Jam; otherJam: Jam }): Wire;
}
export function loadNockchain(source?: string | URL | Uint8Array | ArrayBuffer | WebAssembly.Module): Promise<API>;
