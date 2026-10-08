import { promises as fs } from 'node:fs';
import path from 'node:path';
import { randomUUID } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { canonicalRoot, validateScope, takeSnapshot, fingerprint, artifactRef, atomicJSON, verifyArtifacts, inside, hash } from './snapshot.mjs';
import { describeCheck, parseNative } from './adapters.mjs';
import { executeProcess } from './process.mjs';

const rules = [
  ['locate', /定位|文件和符号|find.*(file|symbol)|locate|search/i, ['native']],
  ['structure', /结构|structure|repo.?map/i, ['native','repo-map']],
  ['complexity', /架构复杂度|复杂度|多层控制|architecture.*complexity|architectural complexity|complex architecture/i, ['native','repo-map']],
  ['entries', /入口|未使用|unused|entry|worker|后台进程/i, ['native','knip']],
  ['execution-files', /运行文件|辅助文件|执行文件|启动文件|runtime files?|helper files?|entry scripts?/i, ['native','knip']],
  ['dependencies', /依赖|循环|dependency|dependencies|cycle|架构规则/i, ['dependency-cruiser']],
  ['clones', /重复代码|克隆|clone|duplicate code/i, ['jscpd']],
  ['control', /逆向|控制关系|reverse|control.?flow/i, ['native','reverse']],
  ['duplicate-controllers', /重复控制器|重复的?调度器|多个控制器|duplicate controllers?|redundant controllers?/i, ['native','reverse','runtime']],
  ['state-provenance', /状态写入|状态来源|state writes?|state provenance/i, ['native','reverse','runtime']],
  ['flow', /跨函数|数据流|data.?flow|taint/i, ['codeql','joern']],
  ['runtime', /异步|并行|取消|调度|状态管理|恢复|重连|断线|任务生命周期|async|parallel|concurren|cancellation|runtime|recovery|reconnect|task lifecycle/i, ['native','runtime']],
  ['configuration', /脚本|配置|环境|config|script|environment/i, ['native','knip']],
  ['configuration-conflict', /配置冲突|配置覆盖|conflicting config|configuration conflict/i, ['native','runtime']],
  ['redundancy', /冗余|重复机制|机制重复|重复控制器|机制.*合并|简化|simplif|redundan|duplicate mechanisms?|merge.*mechanism/i, ['native','reverse']],
  ['safety', /安全架构|安全.*简化|安全边界|security architecture|safe simplification/i, ['native','reverse']],
];
const engineByCapability = Object.fromEntries(rules.map(([cap,,tools])=>[cap,tools]));
export function selectChecks(goal,requiredCapabilities=[]) {
  const capabilities = requiredCapabilities.length ? [...new Set(requiredCapabilities)] : rules.filter(([,regex])=>regex.test(goal)).map(([cap])=>cap);
  if (!capabilities.length) capabilities.push('structure'); // Unknown intent: start with inventory/manual map, not every analyzer.
  const selected = new Map(), gaps=[];
  for(const capability of capabilities) {
    const ids = engineByCapability[capability];
    if(!ids){gaps.push({capability,status:'unsupported',reason:'No native route registered'});continue;}
    // Deep engines are alternatives, not a reason to run both expensive engines.
    for(const id of capability==='flow'?['codeql']:ids) {
      if(!selected.has(id)) selected.set(id,{id,capabilities:[]});
      selected.get(id).capabilities.push(capability);
    }
  }
  return {requiredEvidence:capabilities,selectedChecks:[...selected.values()],gaps};
}

export async function normalizeRequest(input) {
  if(!input || typeof input.goal!=='string' || !input.goal.trim()) throw new Error('A concrete goal is required');
  const root = await canonicalRoot(input.root ?? process.cwd());
  const scope=input.scope ?? ['.'];
  if(!Array.isArray(scope)||!scope.length) throw new Error('scope must contain relative paths');
  await validateScope(root,scope);
  const mode=input.mode ?? 'audit';
  if(!['audit','simplify'].includes(mode)) throw new Error('mode must be audit or simplify');
  if(mode==='simplify' && input.authorized!==true) throw new Error('Simplify requires explicit user authorization; Audit findings do not authorize edits');
  if(input.timeoutMs!==undefined && (!Number.isFinite(input.timeoutMs)||input.timeoutMs<=0)) throw new Error('timeoutMs must be positive');
  return {...input,root,scope,mode,options:input.options??{},generation:input.generation??randomUUID(),timeoutMs:input.timeoutMs??60000};
}

export async function planAnalysis(input,{execute=executeProcess,signal}={}) {
  const request=await normalizeRequest(input);
  const transport=(invocation,opts)=>execute(invocation,{...opts,signal});
  const chosen=selectChecks(request.goal,request.requiredCapabilities);
  const snapshot=await takeSnapshot(request,transport,chosen.selectedChecks);
  if(chosen.requiredEvidence.includes('locate')&&!request.pattern&&/符号|symbol|search|定位.*(?:函数|方法|调用|变量|标识符)/i.test(request.goal)) chosen.gaps.push({capability:'locate',status:'unknown',reason:'A concrete search pattern is required to locate a symbol; inventory alone is insufficient'});
  return {request,snapshot,plan:{id:randomUUID(),...chosen,inputFingerprint:snapshot.id,coverageTarget:request.scope,reuseCandidates:[],stopCondition:'Every required evidence question has supported evidence or an explicit Unknown/Unsupported boundary; native exit zero alone is insufficient'}};
}

function configInputs(request,snapshot,descriptor) {
  return {workspace:snapshot.workspaceId,snapshot:snapshot.id,goal:request.goal,scope:request.scope,pattern:request.pattern??null,engine:descriptor.engine,version:descriptor.version,toolIdentity:descriptor.toolIdentity,options:request.options,config:descriptor.config,capabilities:descriptor.capabilities??null,implementationVersion:2,platform:{os:process.platform,arch:process.arch,node:process.version}};
}

async function findCached(taskDir,key) {
  // Immutable run directories only: no shared head, latest, mutable manifest, or late-writer overwrite.
  let dirs=[];try{dirs=await fs.readdir(path.join(taskDir,'runs'),{withFileTypes:true});}catch{return null;}
  for(const dir of dirs.filter(d=>d.isDirectory())) {
    try {
      const file=path.join(taskDir,'runs',dir.name,'result.json');
      const value=JSON.parse(await fs.readFile(file,'utf8'));
      const item=value.runs?.find(r=>r.cacheKey===key && r.cacheEligible===true);
      if(item && await verifyArtifacts(item.rawArtifacts)) return item;
    }catch{/* A staging/crashed run cannot be reused. */}
  }
  return null;
}

export async function runAnalysis(input,{execute=executeProcess,signal,describe=describeCheck,parse=parseNative,afterRun}={}) {
  const started=performance.now();
  const {request,snapshot,plan}=await planAnalysis(input,{execute,signal});
  if(!request.taskDir) throw new Error('Explicit taskDir is required; analysis artifacts must be isolated from source');
  const taskDir=path.resolve(request.taskDir);
  await fs.mkdir(taskDir,{recursive:true});
  const actualTaskDir=await fs.realpath(taskDir);
  if(inside(request.root,actualTaskDir)) throw new Error('taskDir must be outside the audited workspace to avoid snapshot pollution');
  const runId=randomUUID(),runDir=path.join(actualTaskDir,'runs',runId);
  await fs.mkdir(runDir,{recursive:true});
  const runs=[],evidence=[],gaps=[...plan.gaps],delegations=[];
  let toolCalls=0,cacheHits=0;
  const transport=(invocation,opts)=>execute(invocation,{...opts,signal});
  for(const check of plan.selectedChecks) {
    const artifactDir=path.join(runDir,check.id);await fs.mkdir(artifactDir);
    const descriptor=await describe(check,request,snapshot,artifactDir);
    const key=fingerprint({...configInputs(request,snapshot,descriptor),check});
    if(descriptor.availability!=='available') {
      const boundary={capabilities:check.capabilities,engine:check.id,status:descriptor.availability,reason:descriptor.reason,limitations:descriptor.limitations};
      gaps.push(boundary);
      if(descriptor.delegation) delegations.push({...descriptor.delegation,goal:request.goal,scope:request.scope,snapshotId:snapshot.id,status:'requires_harness'});
      runs.push({runId:`${runId}:${check.id}`,cacheKey:key,cacheEligible:false,tool:descriptor.toolIdentity??{engine:check.id,version:descriptor.version},status:descriptor.availability==='unavailable'?'unavailable':'unsupported',rawArtifacts:[],boundary});
      continue;
    }
    const scopeCacheSafe=snapshot.coverage.scanMode==='project' || check.id==='native';
    const cached= descriptor.cacheSafe!==true || !scopeCacheSafe || snapshot.coverage.truncated || snapshot.coverage.skipped.length ? null : await findCached(actualTaskDir,key);
    if(cached) {
      runs.push({...cached,reusedFrom:cached.runId,runId:`${runId}:${check.id}`,generation:request.generation,metrics:{...cached.metrics,cacheHit:true}});
      evidence.push({...cached.evidence,runId:`${runId}:${check.id}`,snapshotId:snapshot.id,generation:request.generation,reusedFrom:cached.runId});cacheHits++;
      continue;
    }
    const output=await transport(descriptor.invocation,{timeoutMs:request.timeoutMs});toolCalls++;
    const stdoutPath=path.join(artifactDir,'stdout.txt'),stderrPath=path.join(artifactDir,'stderr.txt');
    await fs.writeFile(stdoutPath,output.stdout);await fs.writeFile(stderrPath,output.stderr);
    const extra={};
    for(const file of descriptor.artifactPaths??[]) {try{extra[file]=await fs.readFile(file,'utf8');}catch{}}
    let parsed;try{parsed=parse(check.id,output.stdout,extra);}catch(error){parsed={valid:false,findings:[],coverage:{unresolved:[],skipped:[],parsed:null,truncated:output.truncated},completeness:'unknown',limitations:[`Parse failure: ${error.message}`]};}
    const status=output.status==='completed' && !descriptor.successExitCodes.includes(output.exitCode)?'failed':output.status;
    const artifactFiles=[stdoutPath,stderrPath,...Object.keys(extra)];
    const refs=await Promise.all(artifactFiles.map(file=>artifactRef(file,file===stderrPath?'text/stderr':file===stdoutPath?descriptor.nativeSchema:'native/json',`${runId}:${check.id}`,snapshot,status==='completed'&&parsed.valid?'committed':'failed')));
    const envelope={runId:`${runId}:${check.id}`,workspaceId:snapshot.workspaceId,snapshotId:snapshot.id,generation:request.generation,inputFingerprint:key,provenance:'NATIVE_STATIC',findings:parsed.findings??[],coverage:{requested:request.scope,discovered:snapshot.coverage.discovered,read:'NOT_MEASURED',...parsed.coverage,truncated:Boolean(output.truncated||snapshot.coverage.truncated||parsed.coverage?.truncated)},completeness:status==='completed'&&parsed.valid?parsed.completeness:'unknown',limitations:[...(descriptor.limitations??[]),...(parsed.limitations??[]),'Actual native read set and runtime reachability are not inferred from the file manifest'],nativeArtifacts:refs};
    const nativeFile=check.id==='jscpd'?Object.keys(extra).find(file=>file.endsWith('jscpd-report.json')):stdoutPath;
    for(const finding of envelope.findings){finding.rawArtifactPath=nativeFile??stdoutPath;finding.rawRecordHash=fingerprint(finding.rawRecord);if(check.id==='native')finding.recordLocator={format:request.pattern?'jsonl':'lines',line:Number(finding.rawPointer.slice(1))+1,jsonPointer:request.pattern?'':null};}
    const item={runId:envelope.runId,cacheKey:key,cacheEligible:descriptor.cacheSafe===true&&scopeCacheSafe&&status==='completed'&&parsed.valid&&!output.truncated&&!snapshot.coverage.truncated&&!snapshot.coverage.skipped.length,invocation:descriptor.invocation,tool:{engine:descriptor.engine,version:descriptor.version,...descriptor.toolIdentity},inputs:{fingerprints:configInputs(request,snapshot,descriptor),effectiveConfig:descriptor.config,actualReadSet:'NOT_MEASURED'},platform:{os:process.platform,arch:process.arch,node:process.version},status,startedAt:output.startedAt,finishedAt:output.finishedAt,exitCode:output.exitCode,metrics:{elapsedMs:output.elapsedMs,cacheHit:false,childPeakRSS:'NOT_MEASURED',childCPU:'NOT_MEASURED'},rawArtifacts:refs,evidence:envelope};
    runs.push(item);evidence.push(envelope);
    if(status!=='completed'||!parsed.valid) gaps.push({engine:check.id,capabilities:check.capabilities,status,reason:!parsed.valid?'Native output not valid for known schema':'Native invocation did not finish successfully'});
    if(afterRun) await afterRun({request,snapshot,check,item});
  }
  const finalSnapshot=signal?.aborted?null:await takeSnapshot(request,transport,plan.selectedChecks);
  const stale=finalSnapshot===null||finalSnapshot.id!==snapshot.id;
  if(stale){for(const run of runs){run.cacheEligible=false;for(const ref of run.rawArtifacts)ref.state='failed';}for(const envelope of evidence){envelope.completeness='partial';envelope.limitations.push('Workspace changed or final validation was cancelled; result cannot be reused');}gaps.push({status:signal?.aborted?'cancelled':'unknown',reason:'Input changed or final snapshot unavailable',before:snapshot.id,after:finalSnapshot?.id??null});}
  if(snapshot.coverage.truncated||snapshot.coverage.skipped.length) gaps.push({status:'unknown',reason:'Snapshot coverage was bounded or skipped; cache disabled',coverage:snapshot.coverage});
  const unknownEvidence=evidence.filter(e=>e.completeness!=='complete'||e.coverage.unresolved?.length||e.coverage.truncated);
  const completeness=gaps.length||unknownEvidence.length?'partial':'complete';
  const result={schemaVersion:1,runId,request,snapshot,plan,runs,evidence,gaps,delegations,completeness,stale,simplify:request.mode==='simplify'?{status:'candidate_review_required',authorized:true,editsApplied:false,next:'Use references/simplify.md and existing safe-edit/test-and-verify with responsibility, impact and observed regression evidence'}:null,metrics:{elapsedMs:performance.now()-started,analyzerCalls:toolCalls,cacheHits,discoveryIdentityCalls:4,tokenUsage:'NOT_MEASURED',parentRSSBytes:process.memoryUsage().rss,measurementScope:'single local Node CLI; RSS endpoint, not child process peak'},reportPath:path.join(runDir,'audit.md')};
  await atomicJSON(path.join(runDir,'result.json'),result);
  await fs.writeFile(result.reportPath,renderReport(result));
  return result;
}

export function renderReport(result) {
  const lines=[`# Architecture ${result.request.mode}`,``, `Goal: ${result.request.goal}`,`Workspace: ${result.request.root}`,`Scope: ${result.request.scope.join(', ')}`,`Snapshot: ${result.snapshot.id}`,`Snapshot scan: ${result.snapshot.coverage.scanMode}; discovered: ${result.snapshot.coverage.discovered}; hashed: ${result.snapshot.coverage.hashed}; semantic closure: ${result.snapshot.coverage.semanticClosure}; outside scope: ${result.snapshot.coverage.outsideScope}`,`Completeness: ${result.completeness}; stale: ${result.stale}`,``,`## Native evidence`];
  for(const e of result.evidence){lines.push('',`### ${e.runId.split(':').at(-1)}`,`Coverage: ${e.completeness}; records: ${e.findings.length}; unresolved: ${e.coverage.unresolved?.length??0}`);for(const f of e.findings.slice(0,100)) lines.push(`- ${f.nativeCategory}: ${f.path??'(native record)'}${f.range?`:${f.range.start?.line??f.range.start??''}`:''}; raw pointer ${f.rawPointer}`);if(e.findings.length>100)lines.push(`Display bounded to 100 records; all ${e.findings.length} remain in result.json and native artifacts.`);for(const ref of e.nativeArtifacts)lines.push(`- Raw: ${ref.path} (sha256 ${ref.byteHash})`);for(const limitation of e.limitations) lines.push(`- Limit: ${limitation}`);}
  lines.push('','## Unknown and unsupported');for(const gap of result.gaps)lines.push(`- ${gap.engine??'coverage'}: ${gap.status}; ${gap.reason??''}`);
  for(const delegation of result.delegations)lines.push(`- Harness follow-up: ${JSON.stringify(delegation)}`);
  lines.push('','## Simplify candidates','Unused and clone records are candidates. Neither proves equivalent responsibility or safe deletion. No source files were edited. Dynamic/config-driven entry points, recovery paths and runtime conflicts require confirmation before changes.', '',`Analyzer calls: ${result.metrics.analyzerCalls}; cache hits: ${result.metrics.cacheHits}; elapsed: ${result.metrics.elapsedMs.toFixed(1)} ms; model tokens: NOT_MEASURED.`);
  return lines.join('\n')+'\n';
}

export function assessSimplification({authorized,candidate,baseline}) {
  const blockers=[];
  if(authorized!==true)blockers.push('explicit user modification authorization missing');
  if(candidate?.responsibility!=='confirmed_equivalent')blockers.push('equivalent responsibility not confirmed');
  for(const name of ['dynamicEntryUnknown','configurationPathUnknown','recoveryMechanism','concurrencyOwnershipUnknown','runtimeConflict'])if(candidate?.[name]!==false)blockers.push(name);
  if(!candidate?.evidenceRefs?.length)blockers.push('audit evidence missing');
  if(!candidate?.impactConfirmed)blockers.push('dependencies and impact not confirmed');
  if(baseline?.status!=='passed'||!baseline?.artifactRef)blockers.push('observed behavior baseline missing');
  return {status:blockers.length?'blocked':'ready_for_harness_edit',blockers,editsApplied:false};
}
export function assessRegression({gate,checks,ownedChanges}) {
  if(gate?.status!=='ready_for_harness_edit')return {status:'blocked',success:false};
  if(!checks?.length||checks.some(c=>c.status!=='passed'||!c.artifactRef))return {status:'regression_failed',success:false,next:'Use safe-edit to revert only recorded owned changes; never reset other work',ownedChanges};
  return {status:'verified',success:true,ownedChanges};
}
