import test from 'node:test';
import assert from 'node:assert/strict';
import { access } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadRegistry, planCapabilities } from './route-capabilities.mjs';

const config = await loadRegistry();
const ids = task => planCapabilities(task,config).selectedModules.map(x=>x.id);
const base = {goal:'Identify how state transition works',artifact:{kind:'source'}};

test('every registered reference exists and every dependency resolves',async()=>{
  const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
  for (const cap of Object.values(config.capability_registry)) {
    await access(path.join(root,cap.reference));
    for(const dep of cap.requires) assert.ok(config.capability_registry[dep],dep);
  }
  for(const ref of Object.values(config.platform_routes)) await access(path.join(root,ref));
});

test('semantic needs, not keywords, choose the modules',()=>{
  assert.deepEqual(ids({...base,needs:['control-flow','data-flow']}),['static-map','control-flow','data-flow']);
  assert.deepEqual(ids({...base,goal:'Android Frida Ghidra deobfuscation',needs:['data-flow']}),['static-map','data-flow']);
});

test('platform specialization does not require device-specific main skill',()=>{
  const out=planCapabilities({...base,artifact:{kind:'apk'},needs:['protocol']},config);
  assert.ok(out.references.includes('references/03-android.md'));
  assert.ok(out.selectedModules.some(x=>x.id==='protocol'));
  assert.equal(out.externalHandoffs.length,0);
});

test('requested depth never creates separate quick/deep routing trees',()=>{
  assert.deepEqual(ids({...base,needs:['control-flow'],depth:'deep'}),ids({...base,needs:['control-flow'],depth:'shallow'}));
});

test('dynamic behavior cannot be invented from a phrase',()=>{
  const out=planCapabilities({...base,goal:'frida dynamic reverse',needs:['dynamic-observation']},config);
  assert.equal(out.selectedModules.some(x=>x.id==='dynamic-observation'),false);
  assert.ok(out.gaps.some(x=>x.capability==='dynamic-observation'));
  assert.ok(ids({...base,needs:['dynamic-observation'],runtimeHypothesis:'capture value at call site X',authorizedRuntimeObservation:true}).includes('dynamic-observation'));
});

test('protected and Unity routes require observed signals',()=>{
  assert.ok(!ids({...base,needs:['deobfuscation','unity-il2cpp']}).includes('deobfuscation'));
  assert.ok(ids({...base,needs:['deobfuscation','unity-il2cpp'],verifiedSignals:['packed','global-metadata.dat']}).includes('unity-il2cpp'));
});

test('cross-version needs independent fingerprints',()=>{
  assert.ok(!ids({...base,needs:['version-diff']}).includes('version-diff'));
  assert.ok(ids({...base,artifact:{kind:'source',fingerprints:['sha-a','sha-b']},needs:['version-diff']}).includes('version-diff'));
});

test('architecture review remains independent and never automatic',()=>{
  assert.equal(planCapabilities({...base,needs:['control-flow']},config).externalHandoffs.length,0);
  assert.ok(!ids({...base,needs:['architecture-collaboration']}).includes('architecture-collaboration'));
  const out=planCapabilities({...base,needs:['architecture-collaboration'],allowCrossSkillHandoff:true},config);
  assert.equal(out.externalHandoffs.length,1);
  assert.equal(out.externalHandoffs[0].autoExecute,false);
});

test('unknown target and intent use bounded fallback',()=>{
  const out=planCapabilities({goal:'Understand this unknown artifact',artifact:{kind:'unknown'}},config);
  assert.deepEqual(out.selectedModules.map(x=>x.id),['target-triage']);
  assert.ok(out.gaps.length);
});

test('duplicate semantic capabilities are deduplicated',()=>{
  assert.deepEqual(ids({...base,needs:['protocol','protocol','data-flow']}),['static-map','protocol','data-flow']);
});

test('unsupported capabilities are explicit, not forced into unrelated modules',()=>{
  const out=planCapabilities({...base,needs:['magic-analysis']},config);
  assert.equal(out.status,'unsupported');
  assert.deepEqual(out.selectedModules,[]);
});

test('trace reduction is conditional on a real trace artifact',()=>{
  assert.ok(!ids({...base,needs:['trace-reduction']}).includes('trace-reduction'));
  assert.ok(ids({...base,needs:['trace-reduction'],traceArtifact:'capture-20261009:sha256-123'}).includes('trace-reduction'));
  assert.ok(!ids({...base,goal:'huge log',needs:['data-flow']}).includes('trace-reduction'));
});

test('cross-boundary tracing adds data-flow dependencies only with observed signal',()=>{
  assert.ok(!ids({...base,needs:['boundary-tracing']}).includes('boundary-tracing'));
  assert.deepEqual(ids({...base,needs:['boundary-tracing'],verifiedSignals:['ipc']}),['static-map','data-flow','boundary-tracing']);
  assert.ok(!ids({...base,goal:'JNI app',needs:['data-flow']}).includes('boundary-tracing'));
});

test('differential verification is not version-diff and requires independent cases',()=>{
  assert.ok(!ids({...base,needs:['differential-verification'],comparisonCases:['same','same']}).includes('differential-verification'));
  const out=planCapabilities({...base,needs:['differential-verification'],comparisonCases:['input-A-trace','input-B-trace']},config);
  assert.deepEqual(out.selectedModules.map(x=>x.id),['differential-verification']);
  assert.ok(!out.selectedModules.some(x=>x.id==='version-diff'));
});

test('structured investigation objectives supply missing minimal semantic needs without keyword matching',()=>{
  const out=planCapabilities({goal:'UI Working stuck',artifact:{kind:'source'},objectives:['explain-state']},config);
  assert.equal(out.status,'planned');
  assert.deepEqual(out.selectedModules.map(x=>x.id),['static-map','control-flow','data-flow']);
  assert.deepEqual(ids({goal:'UI Working stuck',artifact:{kind:'source'},needs:['control-flow']}),['static-map','control-flow']);
  assert.deepEqual(ids({goal:'Frida network async',artifact:{kind:'source'},objectives:['explain-call-chain']}),['static-map','control-flow']);
});

test('runtime and version objectives still obey existing gates',()=>{
  const runtime=planCapabilities({goal:'Inspect actual Swift dispatch',artifact:{kind:'ipa'},objectives:['observe-runtime']},config);
  assert.equal(runtime.status,'partial');
  assert.ok(runtime.gaps.some(g=>g.capability==='dynamic-observation'));
  const version=planCapabilities({goal:'Compare implementations',artifact:{kind:'binary-pe'},objectives:['compare-builds']},config);
  assert.ok(version.gaps.some(g=>g.capability==='version-diff'));
});

test('verified in-scope cross-runtime surfaces compose platform adapters without analyzing every file',()=>{
  const out=planCapabilities({goal:'Trace APK native method to Linux library',artifact:{kind:'apk',surfaces:[
    {kind:'binary-elf',evidenceRef:'lib/arm64-v8a/libfoo.so:sha256:observed'}
  ]},objectives:['trace-runtime-boundary'],verifiedSignals:['jni']},config);
  assert.equal(out.status,'planned');
  assert.deepEqual(out.selectedModules.map(x=>x.id),['static-map','data-flow','boundary-tracing']);
  assert.ok(out.references.includes('references/03-android.md'));
  assert.ok(out.references.includes('references/02-native-pe-elf-macho.md'));
  assert.equal(out.references.filter(x=>x==='references/02-native-pe-elf-macho.md').length,1);
});

test('real Swift Mach-O and iOS Swift source load specialist guidance without double native routing',()=>{
  const macho=planCapabilities({goal:'Analyze Swift async resumes',artifact:{kind:'binary-macho'},verifiedSignals:['swift-metadata','swift-async'],objectives:['swift-async-lifecycle']},config);
  assert.equal(macho.status,'planned');
  assert.deepEqual(macho.selectedModules.map(x=>x.id),['static-map','control-flow','data-flow']);
  assert.ok(macho.references.includes('references/02-native-pe-elf-macho.md'));
  assert.ok(macho.references.includes('references/04-ios-macos.md'));
  assert.equal(macho.references.filter(x=>x==='references/04-ios-macos.md').length,1);
  const src=planCapabilities({goal:'Trace iOS Swift source',artifact:{kind:'source'},verifiedSignals:['swift-source','ios-target'],objectives:['swift-protocol-dispatch']},config);
  assert.ok(src.references.includes('references/04-ios-macos.md'));
  assert.deepEqual(src.selectedModules.map(x=>x.id),['static-map','control-flow','structure-recovery']);
});

test('real iOS project families route separately: Swift async, Swift-ObjC, ObjC-only',()=>{
  const remote=planCapabilities({goal:'RemoteAI Swift actor WebSocket event to UI state',
    artifact:{kind:'source'},verifiedSignals:['swift-source','ios-target'],
    objectives:['swift-async-lifecycle','explain-state','reconstruct-protocol']},config);
  assert.equal(remote.status,'planned');
  assert.ok(remote.references.includes('references/04-ios-macos.md'));
  assert.ok(remote.selectedModules.some(x=>x.id==='protocol'));
  assert.ok(!remote.selectedModules.some(x=>x.id==='boundary-tracing'));
  const cloud=planCapabilities({goal:'CloudCode Swift RootHelperBridge.m interop',
    artifact:{kind:'source'},verifiedSignals:['swift-source','objc-source','ios-target','interop'],
    objectives:['objc-swift-bridge']},config);
  assert.equal(cloud.status,'planned');
  assert.equal(cloud.references.filter(x=>x==='references/04-ios-macos.md').length,1);
  assert.ok(cloud.selectedModules.some(x=>x.id==='boundary-tracing'));
  const npi=planCapabilities({goal:'NetworkPolicyInspector Objective-C UIKit app / RootHelper',
    artifact:{kind:'source'},verifiedSignals:['objc-source','ios-target'],
    objectives:['explain-call-chain','trace-data']},config);
  assert.equal(npi.status,'planned');
  assert.ok(npi.references.includes('references/04-ios-macos.md'));
  assert.ok(!npi.selectedModules.some(x=>x.id==='boundary-tracing'));
  assert.ok(!npi.selectedModules.some(x=>x.id==='dynamic-observation'));
});

test('iOS IPA with scoped Mach-O root helper composes Native only for proven helper boundary',()=>{
  const ipa=planCapabilities({
    goal:'NPI Build13 app -> verified bundled NPIRootHelper',
    artifact:{kind:'ipa',surfaces:[{
      kind:'binary-macho',
      evidenceRef:'Build13 IPA sha256=da8097fe64029bfabd6e1a57a9be8dc9569935a5f890b07e008b71560b4d9dd9; embedded NPIRootHelper ARM64 Mach-O observed'
    }]},
    verifiedSignals:['cross-process'],
    objectives:['trace-runtime-boundary','explain-call-chain']
  },config);
  assert.equal(ipa.status,'planned');
  assert.ok(ipa.references.includes('references/04-ios-macos.md'));
  assert.ok(ipa.references.includes('references/02-native-pe-elf-macho.md'));
  assert.ok(ipa.selectedModules.some(x=>x.id==='boundary-tracing'));
  assert.equal(ipa.verification.currentTarget,'unverified');
  const plain=planCapabilities({goal:'Review IPA metadata only',artifact:{kind:'ipa'},needs:['target-triage']},config);
  assert.ok(!plain.references.includes('references/02-native-pe-elf-macho.md'));
  assert.ok(!plain.selectedModules.some(x=>x.id==='boundary-tracing'));
});

test('Swift runtime dispatch and ObjC/Swift bridge do not bypass evidence gates',()=>{
  const bridge=planCapabilities({goal:'Trace @objc Swift selector entry',artifact:{kind:'binary-macho'},verifiedSignals:['swift-metadata'],objectives:['objc-swift-bridge']},config);
  assert.equal(bridge.status,'partial');
  assert.ok(bridge.gaps.some(x=>x.capability==='boundary-tracing'));
  const proven=planCapabilities({goal:'Trace confirmed ObjC Swift handoff',artifact:{kind:'binary-macho'},verifiedSignals:['swift-metadata','interop'],objectives:['objc-swift-bridge']},config);
  assert.equal(proven.status,'planned');
  assert.ok(proven.selectedModules.some(x=>x.id==='boundary-tracing'));
  const runtime=planCapabilities({goal:'Prove async real scheduler run',artifact:{kind:'ipa'},objectives:['ios-runtime-dispatch']},config);
  assert.equal(runtime.status,'partial');
  assert.ok(runtime.gaps.some(x=>x.capability==='dynamic-observation'));
});

test('browser/IDE extension are project kinds, native hosts are scoped sub-artifacts',()=>{
  const out=planCapabilities({goal:'Native messaging from Chrome extension',artifact:{kind:'browser-extension',surfaces:[
    {kind:'javascript',evidenceRef:'manifest background service worker'},
    {kind:'binary-pe',evidenceRef:'native host hashed EXE'}
  ]},objectives:['trace-runtime-boundary'],verifiedSignals:['cross-process']},config);
  assert.equal(out.status,'planned');
  assert.ok(out.references.includes('references/06-electron-flutter-thick-client.md'));
  assert.ok(out.references.includes('references/02-native-pe-elf-macho.md'));
  assert.equal(config.fixture_validation.by_artifact['ide-extension'],'routing_only');
});
