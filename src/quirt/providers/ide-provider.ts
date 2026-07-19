import { createServer, connect } from "node:net";
import { setTimeout as delay } from "node:timers/promises";
import { QUIRT_POWER_OPERATION_GROUPS, type QuirtPowerOperation } from "../power-catalog.js";
import { QuirtError } from "../error.js";
import { publicProviderInstance, safeProviderConfiguration, type QuirtPowerProviderAdapter, type QuirtPowerProviderContext, type QuirtPowerProviderResult } from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";
import { absolutePath, credentialReferences, integer, noBinary, optionalText, providerInstance, providerList, recoverManaged, requiredText, startManagedJob, stopManaged } from "./provider-helpers.js";

async function reservePort(host: string, requested: number | undefined): Promise<number> {
  return await new Promise<number>((resolve, reject) => {
    const server=createServer(); server.unref();
    server.once("error",()=>reject(new QuirtError("port_unavailable","IDE port is unavailable",true)));
    server.listen({host,port:requested??0,exclusive:true},()=>{
      const address=server.address(); const port=typeof address==="object"&&address!==null?address.port:0;
      server.close(cause=>cause===undefined?resolve(port):reject(new QuirtError("port_unavailable","IDE port reservation could not be released",true)));
    });
  });
}

async function listening(host: string, port: number): Promise<boolean> {
  return await new Promise<boolean>(resolve=>{
    const socket=connect({host,port}); const done=(value:boolean):void=>{socket.destroy();resolve(value);};
    socket.setTimeout(500,()=>done(false));socket.once("connect",()=>done(true));socket.once("error",()=>done(false));
  });
}

export class CodeServerProvider implements QuirtPowerProviderAdapter {
  readonly providerId="ide.code-server";
  readonly operationIds=QUIRT_POWER_OPERATION_GROUPS.ide;

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string, unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    noBinary(binary,"IDE");
    switch(operation){
      case "quirt.ide.open": return await this.open(payload,context);
      case "quirt.ide.list": return providerList(context,this.providerId,payload,"IDE");
      case "quirt.ide.repository": return this.repository(payload,context);
      case "quirt.ide.port": return await this.port(payload,context);
      case "quirt.ide.close": return this.close(payload,context);
      default: throw new QuirtError("unknown_operation","IDE operation is unknown");
    }
  }

  async recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext,"ownerPrincipalFingerprint"|"requestId"|"signal">): Promise<void> { await recoverManaged(record,context); }

  private async open(payload: Readonly<Record<string, unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const executable=optionalText(payload.executablePath,"code-server executable path",32_768)??"/usr/bin/code-server";
    await (async()=>{const probe=await context.runtime.probeExecutable(executable,["--version"]);if(!probe.available)throw new QuirtError("executable_missing","code-server is unavailable");if(probe.versionSupported===false)throw new QuirtError("executable_version_unsupported","code-server version is unsupported");})();
    const workspacePath=absolutePath(payload.workspacePath,"IDE workspace path");
    const repositoryPath=payload.repositoryPath===undefined?null:absolutePath(payload.repositoryPath,"IDE repository path");
    const bindAddress=payload.bindAddress===undefined?"127.0.0.1":requiredText(payload.bindAddress,"IDE bind address",64);
    if(bindAddress!=="127.0.0.1"&&bindAddress!=="::1"&&bindAddress!=="localhost")throw new QuirtError("unsafe_listener","IDE listeners must remain private during Checkpoint D");
    const port=await reservePort(bindAddress,payload.port===undefined?undefined:integer(payload.port,"IDE port",0,1,65535));
    const references=credentialReferences(payload.credentialReferences);
    if(typeof references.authentication!=="string")throw new QuirtError("credentials_unavailable","IDE authentication credential reference is required");
    const credentialFile=absolutePath(references.authentication,"IDE authentication credential file reference");
    const expiresAt=payload.expiresInSeconds===undefined?null:new Date(Date.now()+integer(payload.expiresInSeconds,"IDE expiry",3600,60,604800)*1000).toISOString();
    let record=context.state.power.putInstance({
      providerId:this.providerId,providerVersion:"1",ownerPrincipalFingerprint:context.ownerPrincipalFingerprint,targetHost:context.targetHost,state:"starting",
      configuration:safeProviderConfiguration({workspacePath,repositoryPath,bindAddress,port,handoffId:typeof payload.handoffId==="string"?payload.handoffId:null,route:{scheme:"http",host:bindAddress,port,private:true},credentialFileReference:references.authentication}),
      credentialReferences:Object.values(references),ports:[{protocol:"tcp",bindAddress,port,state:"reserved"}],paths:[workspacePath,...(repositoryPath===null?[]:[repositoryPath])],
      relatedSessions:typeof payload.sessionId==="string"?[payload.sessionId]:[],health:{state:"starting"},cleanupStatus:"pending",expiresAt,lastProbeAt:new Date().toISOString()
    });
    context.state.power.recordCredentialReferences(record.instanceId,references);
    context.state.power.recordPort(record.instanceId,{protocol:"tcp",bindAddress,port,state:"reserved"});
    context.state.power.recordIde(record.instanceId,{workspacePath,repositoryPath,route:record.configuration.route as Record<string,unknown>});
    context.state.power.appendEvent(record.instanceId,"lifecycle.starting",{port,privateBinding:true});
    try{
      const launcher="set -eu; PASSWORD=$(cat -- \"$1\"); export PASSWORD; shift; exec \"$@\"";
      record=await startManagedJob(context,record,{executable:context.config.shellPath,arguments:["-c",launcher,"quirt-code-server",credentialFile,executable,"--bind-addr",bindAddress+":"+port,"--auth","password","--disable-telemetry",workspacePath],workingDirectory:workspacePath,eventType:"lifecycle.process-started"});
      const deadline=Date.now()+integer(payload.readinessTimeoutMs,"IDE readiness timeout",30000,100,300000);
      while(Date.now()<deadline&&!await listening(bindAddress,port)){if(context.signal?.aborted===true)throw new QuirtError("canceled","IDE readiness was canceled",true);await delay(100,undefined,{signal:context.signal});}
      if(!await listening(bindAddress,port))throw new QuirtError("readiness_timeout","code-server did not become ready",true);
      record=context.state.power.putInstance({...record,state:"ready",ports:[{protocol:"tcp",bindAddress,port,state:"listening"}],health:{state:"healthy",privateBinding:true},cleanupStatus:"active",lastProbeAt:new Date().toISOString()});
      context.state.power.recordIde(record.instanceId,{workspacePath,repositoryPath,route:record.configuration.route as Record<string,unknown>});
      context.state.power.appendEvent(record.instanceId,"lifecycle.ready",{port});
      return {payload:{ide:publicProviderInstance(record),route:record.configuration.route},instanceId:record.instanceId};
    }catch(cause){
      try{record=stopManaged(context,record,true);}catch{/* preserve original failure */}
      context.state.power.putInstance({...record,state:"failed",failureClassification:cause instanceof QuirtError?cause.code:"internal_error",health:{state:"failed"},cleanupStatus:"complete",lastProbeAt:new Date().toISOString()});
      throw cause;
    }
  }

  private repository(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    let record=providerInstance(context,this.providerId,payload.instanceId,"IDE identity");
    const repositoryPath=absolutePath(payload.repositoryPath,"IDE repository path");
    if(!record.paths.includes(repositoryPath))record=context.state.power.putInstance({...record,configuration:safeProviderConfiguration({...record.configuration,repositoryPath}),paths:[...record.paths,repositoryPath],lastProbeAt:new Date().toISOString()});
    context.state.power.recordIde(record.instanceId,{workspacePath:requiredText(record.configuration.workspacePath,"Stored IDE workspace path",32768),repositoryPath,route:record.configuration.route as Record<string,unknown>});
    context.state.power.appendEvent(record.instanceId,"repository.selected",{repositoryPath});
    return {payload:{ide:publicProviderInstance(record),repositoryPath},instanceId:record.instanceId};
  }

  private async port(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record=providerInstance(context,this.providerId,payload.instanceId,"IDE identity");
    const port=integer(record.configuration.port,"Stored IDE port",0,1,65535);
    const host=requiredText(record.configuration.bindAddress,"Stored IDE bind address",64);
    const ready=await listening(host,port);
    record=context.state.power.putInstance({...record,state:ready?"ready":"degraded",health:{state:ready?"healthy":"degraded",listenerVerified:ready},failureClassification:ready?null:"listener_replaced",lastProbeAt:new Date().toISOString()});
    context.state.power.appendEvent(record.instanceId,"health",{listenerVerified:ready});
    return {payload:{instanceId:record.instanceId,port,bindAddress:host,route:record.configuration.route,listenerVerified:ready},instanceId:record.instanceId};
  }

  private close(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record=providerInstance(context,this.providerId,payload.instanceId,"IDE identity");
    const stopped=stopManaged(context,record,payload.force===true);
    return {payload:{ide:publicProviderInstance(stopped)},instanceId:stopped.instanceId};
  }
}
