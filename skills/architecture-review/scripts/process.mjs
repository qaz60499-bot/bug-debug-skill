import { spawn } from 'node:child_process';
import { performance } from 'node:perf_hooks';
import { StringDecoder } from 'node:string_decoder';

// One-shot native CLI transport. Harness callers may inject their own executor.
// No permissions, retry, task scheduler, process tree recovery or background service.
export async function executeProcess(invocation, {signal,timeoutMs=60000,maxOutputBytes=32*1024*1024}={}) {
  const startedAt = new Date().toISOString(), start = performance.now();
  if (signal?.aborted) return {status:'cancelled',exitCode:null,stdout:'',stderr:'',startedAt,finishedAt:new Date().toISOString(),elapsedMs:0,truncated:false};
  const controller = new AbortController();
  let timedOut=false, stdout='', stderr='', size=0,truncated=false;
  const stdoutDecoder=new StringDecoder('utf8'),stderrDecoder=new StringDecoder('utf8');
  const cancel = () => controller.abort();
  signal?.addEventListener('abort',cancel,{once:true});
  const timer = setTimeout(()=>{timedOut=true;controller.abort();},timeoutMs);
  try {
    return await new Promise(resolve => {
      let error;
      const child = spawn(invocation.executable,invocation.argv,{cwd:invocation.cwd,env:invocation.env?{...process.env,...invocation.env}:process.env,shell:false,windowsHide:true,signal:controller.signal});
      const append = (channel,chunk) => {size+=chunk.length;if(size>maxOutputBytes){truncated=true;controller.abort();return;} if(channel==='stdout') stdout+=stdoutDecoder.write(chunk);else stderr+=stderrDecoder.write(chunk);};
      child.stdout.on('data',chunk=>append('stdout',chunk)); child.stderr.on('data',chunk=>append('stderr',chunk));
      child.on('error',err=>{error=err;});
      child.on('close',(exitCode,exitSignal)=>resolve({status:timedOut?'timed_out':signal?.aborted?'cancelled':error?.code==='ENOENT'?'unavailable':error||truncated||exitSignal?'failed':'completed',exitCode,exitSignal,error:error?.code ?? null,stdout:stdout+stdoutDecoder.end(),stderr:stderr+stderrDecoder.end(),startedAt,finishedAt:new Date().toISOString(),elapsedMs:performance.now()-start,truncated,metrics:{childPeakRSS:'NOT_MEASURED',childCPU:'NOT_MEASURED'}}));
    });
  } finally {clearTimeout(timer);signal?.removeEventListener('abort',cancel);}
}
