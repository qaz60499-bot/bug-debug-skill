import test from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile, writeFile, mkdtemp, rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {performance} from 'node:perf_hooks';
import {loadRegistry,planCapabilities,compactPlan} from './route-capabilities.mjs';

const registry = await loadRegistry();
const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here,'..');
const task = (needs=[],more={})=>({goal:'Inspect unknown behavior without executing target',artifact:{kind:'source'},needs,...more});
const modules = x => planCapabilities(x,registry).selectedModules.map(m=>m.id);

test('cold-load and idle no-target plan is bounded', () => {
  const plan=planCapabilities({goal:'Find out what this is'},registry);
  assert.equal(plan.status,'partial');
  assert.deepEqual(plan.selectedModules.map(m=>m.id),['target-triage']);
  assert.deepEqual(plan.externalHandoffs,[]);
  assert.ok(plan.gaps.length);
});

test('invalid input is rejected before tool selection',()=>{
  for(const bad of [null,[],{}, {goal:''}, {goal:'   '}, {...task(),needs:'protocol'}, {...task(),needs:[null]}, {...task(),artifact:{kind:12}}, {...task(),verifiedSignals:'packed'}]) {
    assert.throws(()=>planCapabilities(bad,registry),{name:'Error'});
  }
});

test('malformed deep capability evidence cannot bypass gates',()=>{
  for (const x of [task(['trace-reduction'],{traceArtifact:12}),task(['differential-verification'],{comparisonCases:'not-array'}),task(['differential-verification'],{comparisonCases:[1,'ok']})]) {
    assert.throws(()=>planCapabilities(x,registry),{name:'Error'});
  }
  const out=planCapabilities(task(['boundary-tracing','trace-reduction','differential-verification'],{verifiedSignals:[],traceArtifact:' ',comparisonCases:['x','x']}),registry);
  assert.ok(['boundary-tracing','trace-reduction','differential-verification'].every(id=>out.gaps.some(g=>g.capability===id)));
});

test('two identical build fingerprints are insufficient for version comparison',()=>{
  const result=planCapabilities(task(['version-diff'],{artifact:{kind:'source',fingerprints:['identical','identical']}}),registry);
  assert.equal(result.selectedModules.some(m=>m.id==='version-diff'),false);
  assert.ok(result.gaps.some(g=>g.capability==='version-diff'));
});

test('prototype inherited capability names cannot activate fake modules',()=>{
  for(const name of ['toString','constructor','__proto__']) {
    const result=planCapabilities(task([name]),registry);
    assert.equal(result.status,'unsupported');
    assert.deepEqual(result.selectedModules,[]);
  }
});

test('prototype inherited artifact kind is treated as unrecognized',()=>{
  const result=planCapabilities(task(['protocol'],{artifact:{kind:'toString'}}),registry);
  assert.ok(result.gaps.some(g=>g.capability==='artifact-classification'));
  assert.ok(result.selectedModules.some(m=>m.id==='target-triage'));
  assert.ok(result.references.every(ref=>typeof ref==='string'));
});

test('registry cycles fail closed',()=>{
  const altered=structuredClone(registry);
  altered.capability_registry['static-map'].requires=['control-flow'];
  assert.throws(()=>planCapabilities(task(['control-flow']),altered),/cycle/i);
});

test('conditional modules fail closed without evidence',()=>{
  for(const name of ['dynamic-observation','deobfuscation','unity-il2cpp','android-framework','function-emulation','version-diff','architecture-collaboration','trace-reduction','boundary-tracing','differential-verification']) {
    const out=planCapabilities(task([name]),registry);
    assert.ok(out.gaps.some(g=>g.capability===name),name);
    assert.equal(out.selectedModules.some(m=>m.id===name),false,name);
  }
});

test('multiple needs and depth are additive, ordered and deduplicated',()=>{
  const result=planCapabilities(task(['protocol','structure-recovery','protocol','control-flow'],{depth:'deep'}),registry);
  assert.deepEqual(result.selectedModules.map(m=>m.id),['static-map','protocol','structure-recovery','control-flow']);
  assert.equal(new Set(result.references).size,result.references.length);
});

test('CLI with valid task is pure JSON output; missing args fails predictably', async ()=>{
  const temp=await mkdtemp(path.join(tmpdir(),'ure-acceptance-'));
  try {
    const file=path.join(temp,'task.json');
    await writeFile(file,JSON.stringify(task(['protocol','data-flow'])),'utf8');
    const proc=spawnSync(process.execPath,[path.join(here,'route-capabilities.mjs'),'--request',file],{cwd:temp,encoding:'utf8',timeout:10000});
    assert.equal(proc.status,0,proc.stderr);
    const out=JSON.parse(proc.stdout);
    assert.deepEqual(out.selectedModules.map(m=>m.id),['static-map','protocol','data-flow']);
    assert.deepEqual(out.externalHandoffs,[]);
    const noarg=spawnSync(process.execPath,[path.join(here,'route-capabilities.mjs')],{cwd:temp,encoding:'utf8',timeout:10000});
    assert.equal(noarg.status,2);
    assert.match(noarg.stderr,/Usage:/);
  } finally {await rm(temp,{recursive:true,force:true});}
});

test('10k empty-load and mixed dry-run plans do not mutate input, leak module state or trigger external work',()=>{
  const list=[
    task(['protocol']),task(['control-flow','data-flow']),
    task(['architecture-collaboration']),task(['version-diff']),
    {goal:'unidentified sample'},
    task(['dynamic-observation'],{runtimeHypothesis:'observe X',authorizedRuntimeObservation:true}),
    task(['boundary-tracing'],{verifiedSignals:['ipc']}),
    task(['trace-reduction'],{traceArtifact:'trace-123'}),
    task(['differential-verification'],{comparisonCases:['case-a','case-b']})
  ];
  const before=JSON.stringify(list);
  const started=performance.now();
  for(let i=0;i<10000;i++){
    const item=list[i%list.length];
    const result=planCapabilities(item,registry);
    assert.equal(result.externalHandoffs.every(x=>x.autoExecute===false),true);
    assert.ok(result.selectedModules.length<=Object.keys(registry.capability_registry).length);
  }
  const elapsed=performance.now()-started;
  assert.equal(JSON.stringify(list),before);
  console.log('10k dry-run plans wall-clock ms:',Math.round(elapsed));
});

test('compact planner projection preserves evidence gates and reduces output',async()=>{
  const request=task(['control-flow','data-flow','trace-reduction'],{artifact:{kind:'electron'}});
  const full=planCapabilities(request,registry);
  const compact=compactPlan(full);
  assert.equal(compact.status,'partial');
  assert.deepEqual(compact.capabilities,full.selectedModules.map(x=>x.id));
  assert.deepEqual(compact.references,full.references);
  assert.deepEqual(compact.gaps,full.gaps);
  assert.ok(!Object.hasOwn(compact,'executionPolicy'));
  assert.ok(!Object.hasOwn(compact,'goal')); // caller already has the goal; avoid echoing large prompts
  assert.ok(JSON.stringify(compact).length < JSON.stringify(full).length*0.65);
  const temp=await mkdtemp(path.join(tmpdir(),'ure-compact-'));
  try {
    const file=path.join(temp,'task.json');
    await writeFile(file,JSON.stringify(request));
    const proc=spawnSync(process.execPath,[path.join(here,'route-capabilities.mjs'),'--request',file,'--compact'],{cwd:temp,encoding:'utf8',timeout:10000});
    assert.equal(proc.status,0,proc.stderr);
    assert.deepEqual(JSON.parse(proc.stdout),compact);
  } finally {await rm(temp,{recursive:true,force:true});}
});

test('every advertised format has explicit case-scoped coverage, never end-to-end by default',()=>{
  const levels = registry.fixture_validation?.by_artifact;
  assert.deepEqual(Object.keys(levels).sort(),Object.keys(registry.platform_routes).sort());
  assert.equal(registry.fixture_validation.meaning.includes('NOT general capability'),true);
  const known = new Set(['routing_only','first_layer_static','bounded_static','static_jni','static_jni_in_apk','asar_container_only','structure_only']);
  for(const [kind,level] of Object.entries(levels)) {
    assert.ok(known.has(level),kind);
    const plan = planCapabilities(task(['control-flow'],{artifact:{kind},depth:'deep'}),registry);
    assert.equal(plan.status,'planned');
    assert.deepEqual(plan.verification,{
      fixtureLevel:level,backend:'not_probed',currentTarget:'unverified'
    },kind);
    assert.deepEqual(compactPlan(plan).verification,plan.verification);
  }
  // A real WASM fixture passed its structure check; complex WASM behavior was NOT recovered.
  assert.equal(levels.wasm,'structure_only');
  assert.equal(levels.electron,'asar_container_only');
  assert.equal(levels['binary-pe'],'first_layer_static');
  for(const kind of ['binary-macho','ipa','dotnet','flutter','firmware','aab']) {
    assert.equal(levels[kind],'routing_only');
  }
});

test('missing coverage entry cannot imply new platform readiness',()=>{
  const changed=structuredClone(registry);
  delete changed.fixture_validation.by_artifact.wasm;
  const out=planCapabilities(task(['control-flow'],{artifact:{kind:'wasm'},depth:'deep'}),changed);
  assert.equal(out.verification.fixtureLevel,'routing_only');
  assert.equal(out.verification.backend,'not_probed');
  assert.equal(out.verification.currentTarget,'unverified');
});

test('objective and sub-artifact contract fails closed for forged/unsupported evidence',()=>{
  for(const bad of [
    task([],{objectives:'explain-state'}),
    task([],{objectives:[null]}),
    task([],{artifact:{kind:'apk',surfaces:'binary-elf'}}),
    task([],{artifact:{kind:'apk',surfaces:[{kind:'binary-elf'}]}}),
    task([],{artifact:{kind:'apk',surfaces:Array.from({length:13},()=>({kind:'binary-elf',evidenceRef:'x'}))}})
  ]) assert.throws(()=>planCapabilities(bad,registry));
  assert.equal(planCapabilities(task([],{objectives:['nonexistent-objective']}),registry).status,'unsupported');
  assert.equal(planCapabilities(task([],{objectives:['constructor']}),registry).status,'unsupported');
  const missing=planCapabilities(task(['protocol'],{artifact:{kind:'apk',surfaces:[{kind:'binary-elf',evidenceRef:' '}]}}),registry);
  assert.equal(missing.status,'partial');
  assert.ok(missing.gaps.some(x=>x.capability==='surface:binary-elf'));
  assert.ok(!missing.references.includes('references/02-native-pe-elf-macho.md'));
  const unknown=planCapabilities(task(['protocol'],{artifact:{kind:'apk',surfaces:[{kind:'fake-platform',evidenceRef:'real file'}]}}),registry);
  assert.equal(unknown.status,'partial');
  assert.ok(!unknown.references.includes('references/02-native-pe-elf-macho.md'));
});

test('Swift specialist overlay requires verified artifact signals, not buzzwords',()=>{
  const generic=planCapabilities({goal:'Swift witness ObjC async',artifact:{kind:'binary-macho'},needs:['control-flow']},registry);
  assert.ok(!generic.references.includes('references/04-ios-macos.md'));
  const source=planCapabilities({goal:'Investigate Swift source not yet platform identified',artifact:{kind:'source'},verifiedSignals:['swift-source'],needs:['control-flow']},registry);
  assert.ok(!source.references.includes('references/04-ios-macos.md'));
  const ios=planCapabilities({goal:'Investigate Swift source targeting iOS',artifact:{kind:'source'},verifiedSignals:['ios-target','swift-source'],needs:['control-flow']},registry);
  assert.ok(ios.references.includes('references/04-ios-macos.md'));
  assert.equal(ios.verification.currentTarget,'unverified');
  for (const overlay of registry.platform_evidence_overlays) assert.ok(registry.platform_routes.ipa===overlay.reference);
});

test('ObjC source specialist guidance requires both actual code and iOS target evidence',()=>{
  const objcOnly=planCapabilities({goal:'Examine Objective-C library',artifact:{kind:'source'},
    verifiedSignals:['objc-source'],needs:['control-flow']},registry);
  assert.ok(!objcOnly.references.includes('references/04-ios-macos.md'));
  const iosOnly=planCapabilities({goal:'Examine native iOS application',artifact:{kind:'source'},
    verifiedSignals:['ios-target'],needs:['control-flow']},registry);
  assert.ok(!iosOnly.references.includes('references/04-ios-macos.md'));
  const real=planCapabilities({goal:'Review iOS Objective-C source and embedded helper',
    artifact:{kind:'source'},verifiedSignals:['ios-target','objc-source'],needs:['control-flow']},registry);
  assert.equal(real.status,'planned');
  assert.ok(real.references.includes('references/04-ios-macos.md'));
  assert.equal(real.verification.currentTarget,'unverified');
  assert.ok(!real.selectedModules.some(x=>x.id==='dynamic-observation'));
});

test('non-target components and unverified dynamic handoffs are not silently auto-activated',()=>{
  const a=planCapabilities({goal:'Inspect Electron UI only',artifact:{kind:'electron'},objectives:['explain-state']},registry);
  assert.equal(a.status,'planned');
  assert.ok(!a.references.includes('references/02-native-pe-elf-macho.md'));
  assert.ok(!a.selectedModules.some(m=>m.id==='boundary-tracing'));
  const b=planCapabilities({goal:'Follow browser extension native messaging',artifact:{kind:'browser-extension'},objectives:['trace-runtime-boundary']},registry);
  assert.equal(b.status,'partial');
  assert.ok(b.gaps.some(g=>g.capability==='boundary-tracing'));
});

test('manifest includes every executable and reference and is the declared version',async()=>{
  const manifest=JSON.parse(await readFile(path.join(root,'manifest.json'),'utf8'));
  assert.equal(manifest.version,registry.version);
  for(const ref of Object.values(registry.platform_routes)) assert.ok(manifest.files.includes(ref),ref);
  for(const m of Object.values(registry.capability_registry)) assert.ok(manifest.files.includes(m.reference),m.reference);
  assert.ok(manifest.files.includes('scripts/route-capabilities.mjs'));
  assert.ok(manifest.files.includes('scripts/test-routing.mjs'));
  assert.ok(manifest.files.includes('scripts/native-triage.py'));
  assert.ok(manifest.files.includes('scripts/test_native_triage.py'));
  assert.ok(manifest.files.includes('scripts/container-triage.py'));
  assert.ok(manifest.files.includes('scripts/test_container_triage.py'));
  for (const ref of ['references/26-evidence-provenance-and-checkpoint.md','references/27-bounded-tool-and-context-budget.md','references/28-deep-trace-boundary-and-differential.md','references/29-stripped-native-toolchain.md']) assert.ok(manifest.files.includes(ref),ref);
});
