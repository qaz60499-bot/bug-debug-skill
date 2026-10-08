import { promises as fs } from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';

export const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === 'object') return Object.fromEntries(Object.keys(value).sort().map(k => [k, stable(value[k])]));
  return value;
}
export const fingerprint = value => hash(JSON.stringify(stable(value)));
export const inside = (root, file) => { const rel = path.relative(root, file); return rel === '' || (!rel.startsWith(`..${path.sep}`) && rel !== '..' && !path.isAbsolute(rel)); };
export async function canonicalRoot(root) { return fs.realpath(path.resolve(root)); }
export async function validateScope(root, scope) {
  for (const item of scope) {
    if (typeof item !== 'string' || item.startsWith('-') || !inside(root, path.resolve(root, item))) throw new Error(`Scope escapes workspace or is an option: ${item}`);
    const actual = await fs.realpath(path.resolve(root, item));
    if (!inside(root, actual)) throw new Error(`Scope symlink escapes workspace: ${item}`);
  }
}
const exclusions = ['node_modules', '.git', '.venv', '__pycache__', 'dist', 'build', '.architecture'];
const configName = /^(package\.json|.*lock.*|tsconfig.*\.json|jsconfig.*\.json|knip.*\.(json|jsonc|js|cjs|mjs|ts)|\.dependency-cruiser.*|\.jscpd.*|pyproject\.toml|requirements.*\.txt|wrangler\.(toml|json|jsonc|ts)|.*\.config\.(js|ts|mjs|cjs))$/i;

// Discover an existing native executable; do not require a caller-specific shell PATH.
// Optional explicit ripgrep location for environments where it is not on PATH.
export async function nativeExecutable(name) {
  const dirs = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
  const suffixes = process.platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  for (const dir of dirs) for (const suffix of suffixes) {
    const candidate = path.join(dir, name + suffix);
    try { await fs.access(candidate); return await fs.realpath(candidate); } catch {}
  }
  if (name === 'rg' && process.env.ARCHITECTURE_RG_PATH) {
    const candidate = path.resolve(process.env.ARCHITECTURE_RG_PATH);
    try { await fs.access(candidate); return await fs.realpath(candidate); } catch {}
  }
  return name; // Preserve the native executor's normal unavailable result.
}

async function scopeConfigPaths(root, scope) {
  const dirs = new Set(['.']);
  for (const item of scope) {
    let parent = path.dirname(item);
    while (parent !== '.' && parent !== path.dirname(parent)) {
      dirs.add(parent);
      parent = path.dirname(parent);
    }
  }
  const paths = [];
  for (const dir of dirs) {
    try {
      for (const entry of await fs.readdir(path.resolve(root, dir), {withFileTypes:true})) {
        if (configName.test(entry.name)) paths.push(path.join(dir,entry.name).replaceAll('\\','/'));
      }
    } catch {} // The requested scope itself was already validated.
  }
  return [...new Set(paths)].sort();
}

export async function takeSnapshot(request, execute, selectedChecks=[]) {
  // Knip's reachability and dependency-cruiser's transitive imports require project-level
  // input identity. Narrow only tools whose native inputs are actually scope-bounded.
  const fullProject = request.scope.some(x=>x==='.' || x==='./') ||
    selectedChecks.some(x=>['knip','dependency-cruiser'].includes(x.id));
  const scanPaths = fullProject ? ['.'] :
    [...new Set([...request.scope, ...await scopeConfigPaths(request.root,request.scope)])];
  const invocation = {executable:await nativeExecutable('rg'), argv:['--files','--no-config','--hidden','--no-ignore', ...exclusions.flatMap(x => ['-g',`!**/${x}/**`]), '--', ...scanPaths], cwd:request.root};
  const listed = await execute(invocation, {timeoutMs:request.timeoutMs});
  if (listed.status !== 'completed' || ![0,1].includes(listed.exitCode)) throw new Error(`Native discovery failed: ${listed.status}: ${listed.stderr}`);
  const discovered = [...new Set(listed.stdout.split(/\r?\n/).filter(Boolean).map(p => p.replaceAll('\\','/').replace(/^\.\//,'')))].sort();
  const files = [], skipped = [];
  const maxFiles = request.maxFiles ?? 10000;
  for (const rel of discovered.slice(0,maxFiles)) {
    const file = path.resolve(request.root, rel);
    try {
      const actual = await fs.realpath(file);
      if (!inside(request.root, actual)) { skipped.push({path:rel,reason:'external symlink'}); continue; }
      const stat = await fs.stat(actual);
      if (!stat.isFile()) {skipped.push({path:rel,reason:'not a regular file'}); continue;}
      if (stat.size > (request.maxFileBytes ?? 16*1024*1024)) { skipped.push({path:rel,reason:'size budget'}); continue; }
      files.push({path:rel,bytesHash:hash(await fs.readFile(actual)),size:stat.size});
    } catch (err) { skipped.push({path:rel,reason:err.code ?? err.message}); }
  }
  const configFiles = files.filter(f => configName.test(path.posix.basename(f.path)));
  const git = await execute({executable:'git',argv:['rev-parse','--absolute-git-dir','--git-common-dir','HEAD'],cwd:request.root},{timeoutMs:request.timeoutMs});
  const gitParts = git.exitCode === 0 ? git.stdout.trim().split(/\r?\n/) : [];
  const identity = {canonicalRoot:request.root, repositoryId:gitParts[1] ? path.resolve(request.root,gitParts[1]) : null,worktreeId:gitParts[0] ?? request.root,revision:gitParts[2] ?? null};
  const contentDigest = fingerprint(files);
  const coverage = {requested:request.scope,scanMode:fullProject?'project':'scoped',scanPaths,semanticClosure:fullProject?'project_files_only':'scope_and_ancestor_configs_only',outsideScope:fullProject?'not_applicable':'NOT_SCANNED',discovered:discovered.length,hashed:files.length,skipped,truncated:listed.truncated || discovered.length>maxFiles,excludedDirectories:exclusions};
  return {id:fingerprint({identity,contentDigest,scanPaths,scanMode:coverage.scanMode}),generation:request.generation,workspaceId:fingerprint(identity),identity,files,configDigest:fingerprint(configFiles),dependenciesDigest:fingerprint(configFiles.filter(f=>/package|lock|requirements|pyproject/.test(f.path))),coverage,discoveryInvocation:invocation,contentDigest};
}

export async function artifactRef(file, schema, ownerRun, snapshot, state='committed') {
  const bytes = await fs.readFile(file);
  return {key:hash(bytes),path:file,nativeSchema:schema,inputFingerprint:snapshot.id,generation:snapshot.generation,byteHash:hash(bytes),bytes:bytes.length,state,ownerRun,retention:'explicit task directory; user owned'};
}
export async function atomicJSON(file,value) {
  const staging = `${file}.${process.pid}.tmp`;
  await fs.writeFile(staging,JSON.stringify(value,null,2)+'\n',{flag:'wx'});
  await fs.rename(staging,file);
}
export async function verifyArtifacts(artifacts) {
  try { for (const item of artifacts) if (hash(await fs.readFile(item.path)) !== item.byteHash || item.state !== 'committed') return false; return true; } catch { return false; }
}
