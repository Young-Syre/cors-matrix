/** Public API. The CLI is a thin wrapper over these. */

export { analyse } from './analyse.js';
export { CaptureError, loadCaptures, parseCaptures, type LoadOptions } from './capture.js';
export { renderAnalysis, renderPlan, renderRules, type Format } from './format.js';
export {
  HeaderMap,
  acaoShapeOf,
  corsCheck,
  readAcao,
  readCorsResponseHeaders,
  requestCarriedCredentials,
  varyCoversOrigin,
} from './headers.js';
export {
  buildTrustAnchors,
  effectivePort,
  hostRelationTo,
  isIpHost,
  originOfUrl,
  parentDomains,
  parseOriginValue,
  relateOrigin,
  sameOrigin,
  type HostRelation,
  type InvalidOrigin,
  type NullOrigin,
  type OriginRelation,
  type OriginValue,
  type TrustAnchors,
  type TupleOrigin,
  type WildcardOrigin,
} from './origin.js';
export { buildPocs, type Poc, type PocBundle, type SkippedPoc } from './poc.js';
export {
  ProbeError,
  buildProbePlan,
  probeCommandHint,
  type Probe,
  type ProbePlan,
  type ProbePlanOptions,
} from './probe.js';
export { RULES, ruleMeta } from './rules.js';
export {
  SEVERITY_ORDER,
  severityRank,
  type AcaoHeader,
  type AcaoShape,
  type AnalysisResult,
  type Capture,
  type CaptureFile,
  type CorsResponseHeaders,
  type Finding,
  type Observation,
  type ObservationInput,
  type PolicySummary,
  type RuleMeta,
  type Severity,
} from './types.js';
