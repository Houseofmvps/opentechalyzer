/**
 * Opentechalyzer public API.
 *
 * @example
 * ```ts
 * import { analyze } from 'opentechalyzer';
 *
 * const result = await analyze('https://example.com', { render: true });
 * for (const tech of result.detections) {
 *   console.log(tech.name, tech.version ?? '', `${tech.confidence}%`);
 * }
 * ```
 */

export { analyze, analyzeMany } from './analyze.js';
export { detect, combineConfidence } from './detect/engine.js';
export {
  BUILTIN_FINGERPRINTS,
  DATABASE_VERSION,
  clearFingerprintCache,
  getFingerprints,
  listCategories,
} from './fingerprints/index.js';
export {
  EXTERNAL_DB_LICENSE_NOTICE,
  externalDatabaseStatus,
  externalDbPath,
  importExternalDatabase,
  loadExternalDatabase,
} from './fingerprints/external.js';
export { isRenderAvailable } from './collect/render.js';
export { formatTerminal, formatMarkdown, formatCsv, summarise } from './report/format.js';
export type {
  AnalyzeOptions,
  AnalyzeResult,
  Category,
  Detection,
  Evidence,
  Evidence_Bundle,
  Fingerprint,
  Pattern,
  PatternInput,
  ProbeSignal,
  SignalSource,
} from './types.js';
