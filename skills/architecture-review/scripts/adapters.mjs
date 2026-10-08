import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { hash, fingerprint, inside, nativeExecutable } from './snapshot.mjs';

const skillDir=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const packages={knip:{name:'knip',bin:'bin/knip.js',schema:'knip/json'},'dependency-cruiser':{name:'dependency-cruiser',bin:'bin/dependency-cruiser.mjs',schema:'dependency-cruiser/json'},jscpd:{name:'jscpd',bin:'bin/jscpd',schema:'jscpd/json'}};
const excludes=['node_modules','.git','.venv','__pycache__','dist','build','.architecture'];
const unavailable=(check,availability,reason,more={})=>({id:check.id,engine:check.id,version:null,availability,reason,config:{},toolIdentity:{engine:check.id,state:'Unavailable'},limitations:[reason],successExitCodes:[],cacheSafe:false,...more});
async function fileIdentity(file){try{const bytes=await fs.readFile(file);return {path:file,byteHash:hash(bytes)};}catch{return {path:file,byteHash:null};}}
async function resolvePackage(id,request){
  const meta=packages[id];
  const roots=[request.toolRoot, path.join(skillDir,'tools','node_modules'),path.join(request.root,'node_modules')].filter(Boolean);
  for(const root of roots){try{
    const base=path.resolve(root,meta.name),manifest=JSON.parse(await fs.readFile(path.join(base,'package.json'),'utf8'));
    const bin=typeof manifest.bin==='string'?manifest.bin:Object.values(manifest.bin??{})[0];
    const executable=path.join(base,bin??meta.bin);
    await fs.access(executable);
    return {base,root,manifest,executable};
  }catch{}}
  return null;
}
async function configIdentity(file){return fileIdentity(file);}
async function installedIdentity(tool){
  const identities=[await fileIdentity(tool.executable),await fileIdentity(path.join(tool.base,'package.json'))];
  for(const file of ['package-lock.json','npm-shrinkwrap.json'])identities.push(await fileIdentity(path.join(tool.root,'..',file)));
  const parsers={};
  for(const name of ['typescript','oxc-parser','oxc-resolver','acorn','enhanced-resolve','@jscpd/core']){
    try{const file=path.join(tool.root,name,'package.json'),pkg=JSON.parse(await fs.readFile(file,'utf8'));parsers[name]={version:pkg.version,...await fileIdentity(file)};}catch{}
  }
  return {installation:tool.base,binIdentity:identities[0],dependencyIdentity:fingerprint(identities),parsers};
}
async function availableConfig(request,option,defaults){
  const explicit=request.options?.[option];
  if(explicit){const file=path.resolve(request.root,explicit);await fs.access(file);return file;}
  for(const rel of defaults){const file=path.join(request.root,rel);try{await fs.access(file);return file;}catch{}}
  return null;
}
export async function describeCheck(check,request,snapshot,artifactDir){
  if(check.id==='native'){
    const executable=await nativeExecutable('rg');
    const probe=spawnSync(executable,['--version'],{encoding:'utf8',windowsHide:true,timeout:3000});
    if(probe.error||probe.status!==0)return unavailable(check,'unavailable','ripgrep executable/version probe unavailable');
    const flags=['--no-config','--hidden','--no-ignore',...excludes.flatMap(x=>['-g',`!**/${x}/**`])];
    const argv=request.pattern?['--json','-n',...flags,'--',request.pattern,...request.scope]:['--files',...flags,'--',...request.scope];
    return {id:check.id,engine:'ripgrep',version:probe.stdout.split(/\r?\n/)[0],availability:'available',invocation:{executable,argv,cwd:request.root},config:{pattern:request.pattern??null,scope:request.scope,excludes,noConfig:true,noIgnore:true},toolIdentity:{versionOutput:probe.stdout.trim(),binIdentity:await fileIdentity(executable),state:'Verified'},successExitCodes:[0,1],nativeSchema:request.pattern?'ripgrep/jsonl':'ripgrep/files',cacheSafe:true,limitations:request.pattern?['Text matches do not establish semantic calls or runtime causality']:['File inventory does not establish symbol, responsibility, configuration effectiveness or entry reachability']};
  }
  if(['repo-map','reverse','runtime'].includes(check.id)){
    const name={'repo-map':'repo-map',reverse:'universal-reverse-engineering',runtime:'bug-triage'}[check.id];
    const file=path.join(skillDir,'..',name,'SKILL.md');
    const exists=await fs.access(file).then(()=>true,()=>false);
    return unavailable(check,exists?'unsupported':'unavailable',check.id==='repo-map'?'Mature Aider RepoMap engine not integrated; installed skill provides a manual structural map':'This evidence requires an existing Harness skill follow-up',{toolIdentity:{engine:check.id,state:exists?'Implemented (Harness delegation)':'Unavailable'},delegation:exists?{skill:name,path:file,requiredEvidence:check.capabilities}:null});
  }
  if(['codeql','joern'].includes(check.id)){
    const probe=spawnSync(check.id,['--version'],{encoding:'utf8',windowsHide:true,timeout:3000,shell:false});
    return unavailable(check,probe.error?.code==='ENOENT'?'unavailable':'unsupported',probe.error?.code==='ENOENT'?`${check.id} native engine is not on PATH`:`${check.id} native execution/query adapter is not implemented; license/platform/language/build/extraction verification required`,{toolIdentity:{engine:check.id,availabilityProbe:probe.status,versionOutput:probe.stdout?.trim()||null,state:probe.error?.code==='ENOENT'?'Unavailable':'Experimental',nativeExecution:'Not Measured'}});
  }
  if(!packages[check.id])return unavailable(check,'unsupported','No adapter implemented');
  const tool=await resolvePackage(check.id,request);
  if(!tool)return unavailable(check,'unavailable',`${check.id} is not installed; audit does not install dependencies`);
  const common={id:check.id,engine:check.id,version:tool.manifest.version,availability:'available',toolIdentity:{...await installedIdentity(tool),state:'Implemented'},successExitCodes:[0],nativeSchema:packages[check.id].schema,cacheSafe:false,limitations:['Analyzer cache reuse disabled: external modules, plugins and environment/configuration closure not fully verified']};
  let args=[],config={};
  try{
    if(check.id==='knip'){
      const configFile=await availableConfig(request,'knipConfig',['knip.json','knip.jsonc','knip.config.ts','knip.config.js','knip.config.mjs']);
      args=['--reporter','json','--no-progress',...(configFile?['--config',configFile]:[])];
      config={configFile:configFile?await configIdentity(configFile):null,scope:request.scope,scopeSemantics:'Knip native project scope; report may extend beyond requested display scope',entryManifest:request.options.entries??null};
      if(request.options.entries?.length&&!configFile)return unavailable(check,'unknown','Explicit entries require a native Knip configuration; no synthetic import graph is substituted');
      common.successExitCodes=[0,1];
      common.env=process.platform==='win32'?{KNIP_DISABLE_RAW_TRANSFER:'1'}:{};
      config.environment=common.env;
      common.toolIdentity.parserMode=process.platform==='win32'?'native standard AST (raw transfer disabled after differential calibration)':'native default';
      common.limitations.push('Unused records are unconfirmed candidates; dynamic/config-driven entry paths require confirmation','Knip uses native project/workspace scope, not a positional file list');
    }else if(check.id==='dependency-cruiser'){
      const configFile=await availableConfig(request,'dependencyConfig',['.dependency-cruiser.cjs','.dependency-cruiser.js','.dependency-cruiser.mjs','.dependency-cruiser.json']);
      const tsConfig=await availableConfig(request,'tsConfig',['tsconfig.json']);
      args=['--output-type','json','--output-to','-','--progress','none',...(configFile?['--config',configFile]:['--no-config']),...(tsConfig?['--ts-config',tsConfig]:[]),'--ts-pre-compilation-deps',...request.scope];
      config={configFile:configFile?await configIdentity(configFile):null,tsConfig:tsConfig?await configIdentity(tsConfig):null,preCompilationDependencies:true,scope:request.scope};
      common.successExitCodes=[0,1];
      common.limitations.push('Variable/computed dynamic imports may be absent from native edges; absence is not proof of unreachability','Native TypeScript environment/skipped warnings remain authoritative');
    }else{
      args=['--reporters','json','--output',artifactDir,'--min-tokens',String(request.options.jscpdMinTokens??50),'--min-lines',String(request.options.jscpdMinLines??5),'--ignore','**/node_modules/**,**/.git/**',...request.scope];
      config={minTokens:request.options.jscpdMinTokens??50,minLines:request.options.jscpdMinLines??5,ignore:'**/node_modules/**,**/.git/**',scope:request.scope};
      common.artifactPaths=[path.join(artifactDir,'jscpd-report.json')];
      common.limitations.push('Textual clones do not prove equivalent behavior or responsibility');
    }
  }catch(error){return unavailable(check,'unknown',`Requested native config unavailable: ${error.message}`);}
    return {...common,config,invocation:{executable:process.execPath,argv:[tool.executable,...args],cwd:request.root,...(common.env?{env:common.env}:{})}};
}

const record=(capability,nativeCategory,pathValue,rawPointer,raw,range=null)=>({capability,nativeCategory,path:pathValue??null,range,rawPointer,rawRecord:raw});
export function parseNative(checkId,rawText,extraArtifacts={}){
  const findings=[],coverage={unresolved:[],skipped:[],truncated:false,parsed:null};
  const limitations=[];
  let native;
  if(checkId==='native'){
    const rows=rawText.split(/\r?\n/).filter(Boolean);
    if(rows[0]?.startsWith('{')){
      native=rows.map(line=>JSON.parse(line));
      for(const [i,r] of native.entries())if(r.type==='match')findings.push(record('locate','text.match',r.data.path?.text,`/${i}`,r,{start:r.data.line_number,end:r.data.line_number}));
    }else{native=rows;for(const [i,file]of rows.entries())findings.push(record('locate','file',file,`/${i}`,file));}
    return {valid:true,native,findings,coverage,completeness:'complete',limitations};
  }
  try{
    const json=checkId==='jscpd'?Object.values(extraArtifacts).find(text=>{try{return Array.isArray(JSON.parse(text).duplicates);}catch{return false;}}):rawText;
    native=JSON.parse(json??'');
    if(checkId==='knip'){
      if(!Array.isArray(native.issues))throw new Error('Expected issues array');
      for(const [i,issue]of native.issues.entries()){
        findings.push(record('entries','knip.issue',issue.file,`/issues/${i}`,issue));
        for(const [category,items]of Object.entries(issue))if(Array.isArray(items))for(const [j,item]of items.entries()){
          findings.push(record('entries',`unused.${category}`,issue.file,`/issues/${i}/${category.replaceAll('~','~0').replaceAll('/','~1')}/${j}`,item,item.line?{start:item.line,end:item.line}:null));
          if(category==='unresolved')coverage.unresolved.push({file:issue.file,...item});
        }
      }
      limitations.push('Native unused categories are candidates, not deletion authorization; entry completeness is not established');
    }else if(checkId==='dependency-cruiser'){
      if(!Array.isArray(native.modules)||!native.summary)throw new Error('Expected modules and summary');
      coverage.parsed=native.modules.map(m=>m.source);
      for(const [i,m]of native.modules.entries()){
        findings.push(record('dependencies','dependency.module',m.source,`/modules/${i}`,m));
        for(const [j,edge]of (m.dependencies??[]).entries()){
          findings.push(record('dependencies','import.dependency',m.source,`/modules/${i}/dependencies/${j}`,edge));
          if(edge.couldNotResolve)coverage.unresolved.push({source:m.source,...edge});
        }
      }
      for(const [i,v]of (native.summary.violations??[]).entries())findings.push(record('dependencies','dependency.violation',v.from,`/summary/violations/${i}`,v));
      coverage.skipped=native.summary.optionsUsed?.exclude? [{nativeExclude:native.summary.optionsUsed.exclude}]:[];
      for(const [i,w]of (native.summary.warnings??[]).entries())findings.push(record('dependencies','dependency.warning',null,`/summary/warnings/${i}`,w));
      if(native.environment)limitations.push(`Native parser/transpiler environment retained in raw /environment; do not infer unsupported language coverage`);
      limitations.push('Computed import targets may have no native unresolved record; their coverage remains unknown');
    }else if(checkId==='jscpd'){
      if(!Array.isArray(native.duplicates)||!native.statistics)throw new Error('Expected duplicates and statistics');
      for(const [i,clone]of native.duplicates.entries())findings.push(record('clones','clone',clone.firstFile?.name,`/duplicates/${i}`,clone,{first:clone.firstFile,second:clone.secondFile}));
      limitations.push('Native clone fragments, endpoints, language and thresholds are retained; semantic equivalence is unknown');
    }else throw new Error('No parser registered');
    return {valid:true,native,findings,coverage,completeness:'partial',limitations};
  }catch(error){return {valid:false,native:null,findings:[],coverage,completeness:'unknown',limitations:[`Native schema/output unsupported: ${error.message}`]};}
}
