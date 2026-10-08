import { promises as fs } from 'node:fs';
import { runAnalysis, planAnalysis } from './router.mjs';

const [command,...args]=process.argv.slice(2);
if(!['audit','plan'].includes(command)||args.length!==2||args[0]!=='--request') {
  console.error('Usage: node architecture.mjs audit|plan --request <request.json>\nRequest: {root, goal, scope:["src"], taskDir:<outside root>, mode:"audit", options:{...}}');process.exitCode=2;
}else {
  const controller=new AbortController();
  const cancel=()=>controller.abort();process.once('SIGINT',cancel);process.once('SIGTERM',cancel);
  try {
    const input=JSON.parse(await fs.readFile(args[1],'utf8'));
    const result=await (command==='plan'?planAnalysis:runAnalysis)(input,{signal:controller.signal});
    if(command==='plan') console.log(JSON.stringify(result,null,2));
    else {console.log(JSON.stringify({runId:result.runId,reportPath:result.reportPath,resultPath:result.reportPath.replace(/audit\.md$/,'result.json'),completeness:result.completeness,metrics:result.metrics,gaps:result.gaps},null,2));process.exitCode=result.runs.some(r=>['failed','cancelled','timed_out'].includes(r.status))?1:0;}
  }catch(err){console.error(JSON.stringify({status:controller.signal.aborted?'cancelled':'failed',error:err.message}));process.exitCode=controller.signal.aborted?130:1;}
  finally {process.removeListener('SIGINT',cancel);process.removeListener('SIGTERM',cancel);}
}
