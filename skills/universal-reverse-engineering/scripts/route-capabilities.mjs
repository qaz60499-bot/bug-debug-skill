// One-shot, side-effect-free capability planner. Semantics are provided by the host Agent.
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export async function loadRegistry() {
  return JSON.parse(await readFile(path.join(root, 'config/routing-v2.json'), 'utf8'));
}

// Optional small CLI projection: does not change planning, gates or execution ownership.
export function compactPlan(plan) {
  return {
    status: plan.status,
    ...(plan.verification ? {verification: plan.verification} : {}),
    ...(plan.artifactKind ? {artifactKind: plan.artifactKind} : {}),
    capabilities: (plan.selectedModules ?? []).map(x => x.id),
    ...(plan.references ? {references: plan.references} : {}),
    ...(plan.externalHandoffs?.length ? {externalHandoffs: plan.externalHandoffs} : {}),
    ...(plan.gaps?.length ? {gaps: plan.gaps} : {})
  };
}

function gateReason(id, task) {
  const signals = new Set(task.verifiedSignals ?? []);
  switch (id) {
    case 'dynamic-observation':
      return typeof task.runtimeHypothesis === 'string' && task.runtimeHypothesis.trim() &&
        task.authorizedRuntimeObservation === true ? null :
        'Requires concrete runtime hypothesis and authorized observation scope';
    case 'deobfuscation':
      return ['packed', 'obfuscated', 'anti-analysis'].some(x => signals.has(x)) ? null :
        'Protection or obfuscation must be observed, not inferred from vocabulary';
    case 'version-diff':
      return Array.isArray(task.artifact?.fingerprints) && task.artifact.fingerprints.length >= 2 &&
        task.artifact.fingerprints.every(x => typeof x === 'string' && x.trim()) &&
        new Set(task.artifact.fingerprints).size >= 2 ? null :
        'At least two distinct, independently identified artifact fingerprints required';
    case 'function-emulation':
      return typeof task.boundedFunction === 'string' && task.boundedFunction.trim() ? null :
        'A bounded target function must be identified';
    case 'unity-il2cpp':
      return ['unity', 'il2cpp', 'global-metadata.dat'].some(x => signals.has(x)) ? null :
        'Requires a verified Unity/IL2CPP indicator';
    case 'android-framework':
      return ['android-framework', 'flutter-android', 'react-native-android'].some(x => signals.has(x)) ? null :
        'Requires a verified Android framework indicator';
    case 'trace-reduction':
      return typeof task.traceArtifact === 'string' && task.traceArtifact.trim() ? null :
        'Requires an identified, actually observed trace or log artifact';
    case 'boundary-tracing':
      return ['ipc','interop','jni','ffi','cross-process','cross-runtime','browser-bridge'].some(x => signals.has(x)) ? null :
        'Cross-runtime/process boundary must be supported by a verified signal';
    case 'differential-verification':
      return Array.isArray(task.comparisonCases) && task.comparisonCases.length >= 2 &&
        task.comparisonCases.every(x => typeof x === 'string' && x.trim()) &&
        new Set(task.comparisonCases).size >= 2 ? null :
        'Requires at least two distinct, identified comparable observations or test cases';
    case 'architecture-collaboration':
      return task.allowCrossSkillHandoff === true ? null :
        'External architecture-review Skill requires an explicit cross-skill handoff decision';
    default: return null;
  }
}

export function planCapabilities(task, registry) {
  if (!task || typeof task.goal !== 'string' || !task.goal.trim()) {
    throw new Error('Nonempty goal is required');
  }
  if (task.needs !== undefined && (!Array.isArray(task.needs) || task.needs.some(n => typeof n !== 'string'))) {
    throw new Error('needs must be a string array of semantic capability IDs');
  }
  if (task.verifiedSignals !== undefined && (!Array.isArray(task.verifiedSignals) || task.verifiedSignals.some(s => typeof s !== 'string'))) {
    throw new Error('verifiedSignals must be a string array');
  }
  // Objectives are interpreted by the host Agent, never inferred from keyword matches.
  if (task.objectives !== undefined && (!Array.isArray(task.objectives) || task.objectives.length > 12 ||
      task.objectives.some(x => typeof x !== 'string' || !x.trim()))) {
    throw new Error('objectives must be a bounded string array');
  }
  if (task.artifact !== undefined && (task.artifact === null || typeof task.artifact !== 'object' || Array.isArray(task.artifact) || (task.artifact.kind !== undefined && typeof task.artifact.kind !== 'string'))) {
    throw new Error('artifact must be an object with a string kind');
  }
  // Include only in-scope, independently inspected sub-artifacts; package names alone are not evidence.
  if (task.artifact?.surfaces !== undefined && (!Array.isArray(task.artifact.surfaces) || task.artifact.surfaces.length > 12 ||
      task.artifact.surfaces.some(s => !s || typeof s !== 'object' || Array.isArray(s) ||
        typeof s.kind !== 'string' || !s.kind.trim() ||
        typeof s.evidenceRef !== 'string'))) {
    throw new Error('artifact.surfaces requires up to 12 {kind,evidenceRef} entries');
  }
  if (task.traceArtifact !== undefined && typeof task.traceArtifact !== 'string') {
    throw new Error('traceArtifact must be a string identifying an observed trace/log');
  }
  if (task.comparisonCases !== undefined && (!Array.isArray(task.comparisonCases) || task.comparisonCases.some(x => typeof x !== 'string'))) {
    throw new Error('comparisonCases must be a string array of identified observations');
  }
  const capabilities = registry.capability_registry;
  const errors = [], gaps = [], selected = new Map(), active = new Set();
  const objectives = [...new Set(task.objectives ?? [])];
  for (const objective of objectives) {
    if (!Object.hasOwn(registry.objective_capabilities ?? {}, objective)) {
      errors.push({capability:'objective:' + objective,reason:'Unregistered investigation objective'});
    }
  }
  const requested = [...new Set([...(task.needs ?? []),
    ...objectives.flatMap(x => Object.hasOwn(registry.objective_capabilities ?? {},x) ? registry.objective_capabilities[x] : [])])];
  for (const id of requested) if (!Object.hasOwn(capabilities,id)) errors.push({ capability: id, reason: 'Unregistered capability' });
  if (errors.length) return { status: 'unsupported', goal: task.goal, selectedModules: [], gaps: errors };

  function select(id, parent) {
    if (selected.has(id)) { selected.get(id).reasons.add(parent); return true; }
    if (active.has(id)) throw new Error('Capability registry dependency cycle at ' + id);
    const module = Object.hasOwn(capabilities,id) ? capabilities[id] : null;
    if (!module) { gaps.push({capability:id,reason:'Unknown dependency'}); return false; }
    const denied = gateReason(id, task);
    if (denied) { gaps.push({capability:id,reason:denied,status:'needs_evidence'}); return false; }
    active.add(id);
    const ok = (module.requires ?? []).every(dep => select(dep, 'dependency:' + id));
    active.delete(id);
    if (!ok) { gaps.push({capability:id,reason:'Prerequisite capability unavailable'}); return false; }
    selected.set(id, {id, reference:module.reference, class:module.class, reasons:new Set([parent])});
    return true;
  }
  for (const id of requested) {
    const origins = objectives.filter(x => (registry.objective_capabilities[x] ?? []).includes(id));
    select(id,(task.needs ?? []).includes(id) ? 'explicit-semantic-need' : 'objective:' + origins[0]);
  }

  const kind = task.artifact?.kind ?? 'unknown';
  if (!Object.hasOwn(registry.platform_routes,kind)) {
    gaps.push({capability:'artifact-classification',status:'needs_evidence',reason:'Unrecognized artifact.kind; run bounded target triage'});
    select('target-triage','unknown-artifact-kind');
  } else if (kind === 'unknown') {
    select('target-triage','unknown-artifact-kind');
  }
  if (requested.length === 0) {
    gaps.push({capability:'task-understanding',status:'needs_evidence',reason:'No specific capability inferred; inspect target and refine the concrete question'});
    select('target-triage','undetermined-intent');
  }

  const platformReferences = [];
  if (kind !== 'unknown' && kind !== 'source' && Object.hasOwn(registry.platform_routes,kind)) {
    platformReferences.push(registry.platform_routes[kind]);
  }
  for (const surface of task.artifact?.surfaces ?? []) {
    if (!Object.hasOwn(registry.platform_routes,surface.kind) || surface.kind === 'unknown' || !surface.evidenceRef.trim()) {
      gaps.push({capability:'surface:' + surface.kind,status:'needs_evidence',
        reason:'In-scope sub-artifact must have a registered kind and a real inspected evidence reference'});
      select('target-triage','unverified-sub-artifact');
      continue;
    }
    // This is an evidence reference supplied by the Agent, not an independently verified fingerprint.
    // The executing Agent must validate it against the actual target before treating the route as proven.
    if (surface.kind !== 'source') platformReferences.push(registry.platform_routes[surface.kind]);
  }
  // Match specialist guidance to observed format/runtime, not an extension or wishful goal.
  // This is a reference overlay inside the same planner, not another dispatcher or tool invocation.
  const verified = new Set(task.verifiedSignals ?? []);
  for (const overlay of registry.platform_evidence_overlays ?? []) {
    if ((overlay.kinds ?? []).includes(kind) &&
        (overlay.signals === undefined || overlay.signals.some(signal => verified.has(signal))) &&
        (overlay.allSignals === undefined || overlay.allSignals.every(signal => verified.has(signal)))) {
      platformReferences.push(overlay.reference);
    }
  }
  const selectedModules = [...selected.values()].map(({reasons,...item})=>({...item,reasons:[...reasons]}));
  const references = [...new Set([...platformReferences,...selectedModules.filter(x=>x.class!=='external_optional').map(x=>x.reference)].filter(Boolean))];
  const handoffs = selectedModules.filter(x => x.class === 'external_optional').map(x => ({
    capability:x.id, externalSkill:'architecture-review',
    mode:'evidence-handoff-only', autoExecute:false,
    requirement:'Existing host skill availability, authorization, scoped evidence question and independent ownership'
  }));
  const caseLevel = Object.hasOwn(registry.fixture_validation?.by_artifact ?? {},kind) ?
    registry.fixture_validation.by_artifact[kind] : 'routing_only';
  // Past fixture-level evidence is NEVER a live backend probe or current target success.
  const verification = {fixtureLevel:caseLevel,backend:'not_probed',currentTarget:'unverified'};
  return {
    status: gaps.length ? 'partial' : 'planned',
    verification,
    goal:task.goal, artifactKind:kind, depth:task.depth ?? 'user-defined-or-proportional',
    selectedModules, references, externalHandoffs:handoffs, gaps,
    executionPolicy:{
      ownership:'Host Agent; this planner does not invoke tools or specialist skills',
      order:'Dependencies before dependants; independent evidence gathering may run concurrently within budget',
      evidence:'Observation / Inference / Unknown; fingerprint per artifact for cross-build claims; separate original/tool-derived/agent-proposed/independent-oracle',
      retrieval:'Prefer scoped, paginated tool queries with count/coverage/truncation, not bulk context dumps; only use available authorized backends',
      retry:'After two equivalent failures, revise hypothesis or backend rather than blindly vary parameters',
      resume:'Reuse checkpoint only after artifact, tool/database state and dependent evidence are revalidated',
      stop:'Sufficient reproducible evidence for user goal, or explicit Unknown/Unsupported'
    }
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if ((args.length !== 2 && args.length !== 3) || args[0] !== '--request' || (args.length === 3 && args[2] !== '--compact')) {
    console.error('Usage: node scripts/route-capabilities.mjs --request <task-descriptor.json> [--compact]');
    process.exitCode = 2;
  } else {
    try {
      const task = JSON.parse(await readFile(path.resolve(args[1]), 'utf8'));
      const plan = planCapabilities(task, await loadRegistry());
      console.log(JSON.stringify(args[2] === '--compact' ? compactPlan(plan) : plan, null, args[2] === '--compact' ? 0 : 2));
    } catch (error) {
      console.error(JSON.stringify({status:'invalid',error:error.message}));
      process.exitCode = 1;
    }
  }
}
