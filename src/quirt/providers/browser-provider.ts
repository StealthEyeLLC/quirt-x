import { createHash, randomUUID } from "node:crypto";
import { createReadStream } from "node:fs";
import { chmod, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { BrowserContext, Download, Page } from "playwright-core";
import { QUIRT_POWER_OPERATION_GROUPS, type QuirtPowerOperation } from "../power-catalog.js";
import { QuirtError } from "../error.js";
import { publicProviderInstance, safeProviderConfiguration, type QuirtPowerProviderAdapter, type QuirtPowerProviderContext, type QuirtPowerProviderResult } from "../power-provider.js";
import type { QuirtProviderInstanceRecord } from "../power-state.js";
import { absolutePath, integer, noBinary, optionalText, providerInstance, providerList, requiredText, stopManaged } from "./provider-helpers.js";

interface LiveBrowser {
  context: BrowserContext;
  contextId: string;
  pages: Map<string, Page>;
  pageIds: Map<Page, string>;
  selectedPageId: string | null;
  downloads: Map<string, { path: string; suggestedFilename: string; sha256: string; sizeBytes: number }>;
  eventDisposers: Array<() => void>;
}

function bounded(value: string, maximum: number): { value: string; truncated: boolean } {
  const bytes=Buffer.from(value);
  return bytes.length<=maximum?{value,truncated:false}:{value:bytes.subarray(0,maximum).toString("utf8"),truncated:true};
}

function safeUrl(value: unknown): string {
  const raw=requiredText(value,"Browser URL",32_768);
  let url: URL; try{url=new URL(raw);}catch{throw new QuirtError("invalid_request","Browser URL is invalid");}
  if(!["http:","https:","file:"].includes(url.protocol)||url.username.length>0||url.password.length>0)throw new QuirtError("invalid_request","Browser URL scheme or credentials are unsafe");
  return url.href;
}

async function digestFile(path: string): Promise<{sha256:string;sizeBytes:number}> {
  const hash=createHash("sha256");let sizeBytes=0;
  for await(const chunk of createReadStream(path)){const bytes=Buffer.isBuffer(chunk)?chunk:Buffer.from(chunk);hash.update(bytes);sizeBytes+=bytes.length;}
  return {sha256:hash.digest("hex"),sizeBytes};
}

async function directChildProcessIds(): Promise<Set<number>> {
  try {
    const text=await readFile(`/proc/self/task/${process.pid}/children`,"utf8");
    return new Set(text.trim().split(/\s+/u).filter(Boolean).map(Number).filter((pid)=>Number.isSafeInteger(pid)&&pid>1));
  } catch {
    return new Set();
  }
}

type PlaywrightLoader = () => Promise<Pick<typeof import("playwright-core"), "chromium" | "firefox" | "webkit">>;

export class PlaywrightBrowserProvider implements QuirtPowerProviderAdapter {
  readonly providerId="browser.playwright";
  readonly operationIds=QUIRT_POWER_OPERATION_GROUPS.browser;
  readonly #live=new Map<string,LiveBrowser>();

  constructor(private readonly loadPlaywright: PlaywrightLoader = () => import("playwright-core")) {}

  async execute(operation: QuirtPowerOperation, payload: Readonly<Record<string,unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    if(operation!=="quirt.browser.upload")noBinary(binary,"Browser");
    switch(operation){
      case "quirt.browser.open": return await this.open(payload,context);
      case "quirt.browser.list": return providerList(context,this.providerId,payload,"Browser");
      case "quirt.browser.command": return await this.command(payload,context);
      case "quirt.browser.screenshot": return await this.screenshot(payload,context);
      case "quirt.browser.video": return await this.video(payload,context);
      case "quirt.browser.download": return this.download(payload,context);
      case "quirt.browser.upload": return await this.upload(payload,binary,context);
      case "quirt.browser.show": return this.show(payload,context);
      case "quirt.browser.close": return await this.close(payload,context);
      default: throw new QuirtError("unknown_operation","Browser operation is unknown");
    }
  }

  async recover(record: QuirtProviderInstanceRecord, context: Omit<QuirtPowerProviderContext,"ownerPrincipalFingerprint"|"requestId"|"signal">): Promise<void> {
    context.state.power.putInstance({...record,state:"lost",failureClassification:"browser_crashed",recoveryClassification:"persistent_storage_preserved_pages_lost",health:{state:"lost",persistentStoragePreserved:true,inMemoryPagesRecovered:false},lastProbeAt:new Date().toISOString()});
    context.state.power.recordRecovery(record.instanceId,"persistent_storage_preserved_pages_lost",{paths:record.paths});
    context.state.power.appendEvent(record.instanceId,"browser.crash",{persistentStoragePreserved:true,inMemoryPagesRecovered:false});
  }

  private async open(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let playwright: Awaited<ReturnType<PlaywrightLoader>>;
    try{playwright=await this.loadPlaywright();}catch{throw new QuirtError("provider_unavailable","Pinned playwright-core dependency is unavailable");}
    const engine=payload.engine==="firefox"||payload.engine==="webkit"||payload.engine==="chromium"?payload.engine:"chromium";
    const browserType=playwright[engine];
    const executablePath=optionalText(payload.executablePath,"Browser executable path",32_768)??(engine==="chromium"?"/usr/bin/chromium":undefined);
    if(executablePath!==undefined){const probe=await context.runtime.probeExecutable(executablePath,["--version"]);if(!probe.available)throw new QuirtError("executable_missing","Requested browser engine executable is unavailable");}
    const instanceId=randomUUID();
    const userDataPath=payload.userDataPath===undefined?join(context.config.stateRoot,"providers","browser",instanceId):absolutePath(payload.userDataPath,"Browser user-data path");
    await mkdir(userDataPath,{recursive:true,mode:0o700});await chmod(userDataPath,0o700);
    const headless=payload.headless!==false;
    const viewport=payload.viewport===undefined?{width:1280,height:720}:{width:integer((payload.viewport as Record<string,unknown>).width,"Browser viewport width",1280,200,7680),height:integer((payload.viewport as Record<string,unknown>).height,"Browser viewport height",720,200,4320)};
    let record=context.state.power.putInstance({instanceId,providerId:this.providerId,providerVersion:"1",ownerPrincipalFingerprint:context.ownerPrincipalFingerprint,targetHost:context.targetHost,state:"starting",configuration:safeProviderConfiguration({engine,headless,executablePath,viewport,userDataPath}),paths:[userDataPath],health:{state:"starting"},cleanupStatus:"pending",lastProbeAt:new Date().toISOString()});
    context.state.power.appendEvent(instanceId,"lifecycle.starting",{engine,headless});
    const childProcessesBefore=await directChildProcessIds();
    let browserContext: BrowserContext;
    try{
      browserContext=await browserType.launchPersistentContext(userDataPath,{headless,executablePath,viewport,acceptDownloads:true,downloadsPath:join(userDataPath,"downloads"),recordVideo:payload.recordVideo===true?{dir:join(userDataPath,"videos"),size:viewport}:undefined});
    }catch(cause){
      record=context.state.power.putInstance({...record,state:"failed",failureClassification:"browser_crashed",health:{state:"failed"},cleanupStatus:"complete",lastProbeAt:new Date().toISOString()});
      context.state.power.appendEvent(instanceId,"failure",{errorCode:"browser_crashed"});
      throw new QuirtError("browser_crashed",cause instanceof Error?bounded(cause.message,512).value:"Browser launch failed",true);
    }
    const processIdentities: Readonly<Record<string,unknown>>[]=[];
    for(const pid of await directChildProcessIds()){
      if(childProcessesBefore.has(pid))continue;
      try{
        const identity=await context.runtime.processIdentity(pid);
        processIdentities.push(identity);
        context.state.power.recordProcess(instanceId,identity);
      }catch{/* a browser child may exit or re-parent during launch; health reports the unverified identity */}
    }
    const contextId=randomUUID();const live:LiveBrowser={context:browserContext,contextId,pages:new Map(),pageIds:new Map(),selectedPageId:null,downloads:new Map(),eventDisposers:[]};
    this.#live.set(instanceId,live);
    context.state.power.recordBrowser(instanceId,{engine,userDataPath,state:{headless,viewport,persistent:true}});
    context.state.power.recordBrowserContext(contextId,instanceId,{persistent:true,userDataPath,storageProtected:true});
    const register=(page:Page):string=>{
      const existing=live.pageIds.get(page);if(existing!==undefined)return existing;
      const pageId=randomUUID();live.pages.set(pageId,page);live.pageIds.set(page,pageId);live.selectedPageId=pageId;
      context.state.power.recordBrowserPage(pageId,contextId,{url:page.url(),state:"open",viewport});
      const consoleHandler=(message:{type():string;text():string}):void=>{const item=bounded(message.text(),8192);context.state.power.appendBrowserEvent(instanceId,"console",pageId,{type:message.type(),text:item.value,truncated:item.truncated});};
      const errorHandler=(error:Error):void=>{const item=bounded(error.message,8192);context.state.power.appendBrowserEvent(instanceId,"page-error",pageId,{message:item.value,truncated:item.truncated});};
      const requestHandler=(request:{url():string;method():string;resourceType():string}):void=>{context.state.power.appendBrowserEvent(instanceId,"request",pageId,{url:bounded(request.url(),4096).value,method:request.method(),resourceType:request.resourceType()});};
      const responseHandler=(response:{url():string;status():number}):void=>{context.state.power.appendBrowserEvent(instanceId,"response",pageId,{url:bounded(response.url(),4096).value,status:response.status()});};
      const closeHandler=():void=>{live.pages.delete(pageId);live.pageIds.delete(page);if(live.selectedPageId===pageId)live.selectedPageId=live.pages.keys().next().value??null;context.state.power.recordBrowserPage(pageId,contextId,{url:page.url(),state:"closed"});context.state.power.appendBrowserEvent(instanceId,"page-closed",pageId,{});};
      const downloadHandler=async(download:Download):Promise<void>=>{
        const downloadId=randomUUID();
        try{
          const path=await download.path();
          if(path===null){context.state.power.appendBrowserEvent(instanceId,"download-failed",pageId,{downloadId,reason:"path_unavailable"});return;}
          const digest=await digestFile(path);
          const item={path,suggestedFilename:bounded(download.suggestedFilename(),1024).value,...digest};
          live.downloads.set(downloadId,item);
          context.state.power.appendBrowserEvent(instanceId,"download",pageId,{downloadId,suggestedFilename:item.suggestedFilename,sha256:item.sha256,sizeBytes:item.sizeBytes});
        }catch{context.state.power.appendBrowserEvent(instanceId,"download-failed",pageId,{downloadId,reason:"download_unavailable"});}
      };
      page.on("console",consoleHandler);page.on("pageerror",errorHandler);page.on("request",requestHandler);page.on("response",responseHandler);page.on("download",(download)=>{void downloadHandler(download);});page.once("close",closeHandler);
      return pageId;
    };
    for(const page of browserContext.pages())register(page);
    browserContext.on("page",register);
    browserContext.on("close",()=>{if(this.#live.delete(instanceId)){context.state.power.putInstance({...record,state:"lost",failureClassification:"browser_crashed",health:{state:"lost"},lastProbeAt:new Date().toISOString()});context.state.power.appendBrowserEvent(instanceId,"crash",null,{persistentStoragePreserved:true});}});
    browserContext.on("request",()=>{/* page-level hooks carry bounded network metadata */});
    browserContext.on("close",()=>{/* durable close/crash classification above */});
    const pages=[...live.pages.entries()].map(([pageId,page])=>({pageId,url:page.url()}));
    record=context.state.power.putInstance({...record,state:"ready",processIdentities,health:{state:"healthy",engine,persistent:true,processIdentityVerified:processIdentities.length>0,processIdentityCount:processIdentities.length},cleanupStatus:"active",lastProbeAt:new Date().toISOString()});
    context.state.power.appendEvent(instanceId,"lifecycle.ready",{contextId,pageCount:pages.length,processIdentityVerified:processIdentities.length>0,processIdentityCount:processIdentities.length});
    return {payload:{browser:publicProviderInstance(record),contextId,pages,selectedPageId:live.selectedPageId},instanceId};
  }

  private page(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): {record:QuirtProviderInstanceRecord;live:LiveBrowser;page:Page;pageId:string} {
    const record=providerInstance(context,this.providerId,payload.instanceId,"Browser identity");const live=this.#live.get(record.instanceId);
    if(live===undefined)throw new QuirtError("browser_crashed","Browser process is not live");
    const pageId=optionalText(payload.pageId,"Browser page identity",128)??live.selectedPageId;
    if(pageId===null||pageId===undefined)throw new QuirtError("page_gone","Browser page is unavailable");
    const page=live.pages.get(pageId);if(page===undefined||page.isClosed())throw new QuirtError("page_gone","Browser page is unavailable");
    return {record,live,page,pageId};
  }

  private async command(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const action=requiredText(payload.action,"Browser action",64);
    if(action==="page.new"){
      const record=providerInstance(context,this.providerId,payload.instanceId,"Browser identity");const live=this.#live.get(record.instanceId);if(live===undefined)throw new QuirtError("browser_crashed","Browser process is not live");
      const page=await live.context.newPage();let pageId=live.pageIds.get(page);if(pageId===undefined){pageId=randomUUID();live.pages.set(pageId,page);live.pageIds.set(page,pageId);live.selectedPageId=pageId;context.state.power.recordBrowserPage(pageId,live.contextId,{url:page.url(),state:"open"});}
      return {payload:{instanceId:record.instanceId,pageId,url:page.url()},instanceId:record.instanceId};
    }
    const {record,live,page,pageId}=this.page(payload,context);let result:unknown=null;
    switch(action){
      case "page.select": live.selectedPageId=pageId;result={selected:true};break;
      case "navigate": result=await page.goto(safeUrl(payload.url),{waitUntil:payload.waitUntil==="load"||payload.waitUntil==="domcontentloaded"||payload.waitUntil==="networkidle"||payload.waitUntil==="commit"?payload.waitUntil:"load",timeout:integer(payload.timeoutMs,"Navigation timeout",30000,1,300000)}).then(response=>({url:page.url(),status:response?.status()??null}));break;
      case "wait": {
        const selector=optionalText(payload.selector,"Browser selector",16_384);
        if(selector===undefined)await page.waitForTimeout(integer(payload.timeoutMs,"Browser wait timeout",1000,0,300000));else await page.locator(selector).waitFor({state:payload.state==="attached"||payload.state==="detached"||payload.state==="hidden"||payload.state==="visible"?payload.state:"visible",timeout:integer(payload.timeoutMs,"Browser wait timeout",30000,1,300000)});
        result={completed:true};break;
      }
      case "click": await page.locator(requiredText(payload.selector,"Browser selector",16_384)).click({timeout:integer(payload.timeoutMs,"Browser click timeout",30000,1,300000)});result={clicked:true};break;
      case "type": await page.locator(requiredText(payload.selector,"Browser selector",16_384)).fill(requiredText(payload.text,"Browser text",1_048_576),{timeout:integer(payload.timeoutMs,"Browser type timeout",30000,1,300000)});result={typed:true};break;
      case "keyboard": await page.keyboard.press(requiredText(payload.key,"Browser key",256));result={pressed:true};break;
      case "mouse": {
        const mouseAction=payload.mouseAction==="move"?"move":"click";const x=integer(payload.x,"Browser mouse X",0,0,100000);const y=integer(payload.y,"Browser mouse Y",0,0,100000);
        if(mouseAction==="move")await page.mouse.move(x,y);else await page.mouse.click(x,y,{button:payload.button==="right"||payload.button==="middle"?payload.button:"left"});
        result={mouseAction,x,y};break;
      }
      case "evaluate": {
        const expression=requiredText(payload.expression,"Browser evaluation expression",1_048_576);const value=await page.evaluate(expression);const serialized=JSON.stringify(value);const pageResult=bounded(serialized===undefined?"null":serialized,integer(payload.maximumBytes,"Browser evaluation bound",262144,1,1048576));result={json:pageResult.value,truncated:pageResult.truncated};break;
      }
      case "content": {const pageResult=bounded(await page.content(),integer(payload.maximumBytes,"Browser content bound",262144,1,1048576));result={content:pageResult.value,truncated:pageResult.truncated};break;}
      case "accessibility": {const snapshot=await page.locator("body").ariaSnapshot({timeout:integer(payload.timeoutMs,"Accessibility timeout",30000,1,300000)});const pageResult=bounded(snapshot,integer(payload.maximumBytes,"Accessibility bound",262144,1,1048576));result={snapshot:pageResult.value,truncated:pageResult.truncated};break;}
      case "cookies": result={cookies:await live.context.cookies()};break;
      case "storageState": {
        const storagePath=payload.path===undefined?join(requiredText(record.configuration.userDataPath,"Stored browser path",32768),"storage-state.json"):absolutePath(payload.path,"Browser storage-state path");
        await live.context.storageState({path:storagePath});await chmod(storagePath,0o600);const digest=await digestFile(storagePath);result={path:storagePath,...digest,protected:true};break;
      }
      case "viewport": {const viewport={width:integer(payload.width,"Browser viewport width",1280,200,7680),height:integer(payload.height,"Browser viewport height",720,200,4320)};await page.setViewportSize(viewport);result={viewport};break;}
      case "pdf": {const outputPath=absolutePath(payload.path,"Browser PDF path");const bytes=await page.pdf({path:outputPath,printBackground:payload.printBackground!==false});await chmod(outputPath,0o600);result={path:outputPath,sha256:createHash("sha256").update(bytes).digest("hex"),sizeBytes:bytes.length};break;}
      case "events": {
        const events=context.state.power.readEvents(record.instanceId,context.ownerPrincipalFingerprint,context.targetHost,integer(payload.after,"Browser event cursor",-1,-1,Number.MAX_SAFE_INTEGER),integer(payload.maximumEvents,"Browser event page size",100,1,1000));result=events;break;
      }
      case "page.close": await page.close();result={closed:true};break;
      default: throw new QuirtError("invalid_request","Browser action is unsupported");
    }
    context.state.power.recordBrowserPage(pageId,live.contextId,{url:page.isClosed()?"":page.url(),state:page.isClosed()?"closed":"open",selected:live.selectedPageId===pageId});
    context.state.power.appendBrowserEvent(record.instanceId,"command",pageId,{action});
    return {payload:{instanceId:record.instanceId,pageId,action,result},instanceId:record.instanceId};
  }

  private async screenshot(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const {record,page,pageId}=this.page(payload,context);const path=payload.path===undefined?undefined:absolutePath(payload.path,"Browser screenshot path");
    const bytes=await page.screenshot({path,fullPage:payload.fullPage===true,type:payload.type==="jpeg"?"jpeg":"png",quality:payload.type==="jpeg"?integer(payload.quality,"Screenshot quality",80,1,100):undefined});
    const digest=createHash("sha256").update(bytes).digest("hex");context.state.power.appendBrowserEvent(record.instanceId,"screenshot",pageId,{path:path??null,sha256:digest,sizeBytes:bytes.length});
    const maximum=integer(payload.maximumBytes,"Screenshot result bound",1048576,1,Math.min(context.config.maxFrameBytes-4096,8*1048576));
    if(bytes.length>maximum){if(path===undefined)throw new QuirtError("output_truncated","Screenshot exceeds the bounded result; request a protected path");return {payload:{instanceId:record.instanceId,pageId,path,sha256:digest,sizeBytes:bytes.length,inline:false},instanceId:record.instanceId};}
    return {payload:{instanceId:record.instanceId,pageId,path:path??null,sha256:digest,sizeBytes:bytes.length,inline:true},binary:bytes,instanceId:record.instanceId};
  }

  private async video(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const {record,page,pageId}=this.page(payload,context);const video=page.video();if(video===null)throw new QuirtError("provider_unavailable","Browser video recording was not enabled for this context");
    const path=await video.path();const digest=await digestFile(path);return {payload:{instanceId:record.instanceId,pageId,path,...digest},instanceId:record.instanceId};
  }

  private download(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record=providerInstance(context,this.providerId,payload.instanceId,"Browser identity");const live=this.#live.get(record.instanceId);if(live===undefined)throw new QuirtError("browser_crashed","Browser process is not live");
    const downloadId=requiredText(payload.downloadId,"Browser download identity",128);const download=live.downloads.get(downloadId);if(download===undefined)throw new QuirtError("not_found","Browser download was not found");
    return {payload:{instanceId:record.instanceId,downloadId,...download},instanceId:record.instanceId};
  }

  private async upload(payload: Readonly<Record<string,unknown>>, binary: Buffer, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    const {record,page,pageId}=this.page(payload,context);const selector=requiredText(payload.selector,"Browser upload selector",16_384);
    let path:string;let temporaryPath:string|null=null;
    if(binary.length>0){if(binary.length>8*1024*1024)throw new QuirtError("output_truncated","Inline browser upload exceeds the bounded transfer size");const uploads=join(requiredText(record.configuration.userDataPath,"Stored browser path",32768),"uploads");await mkdir(uploads,{recursive:true,mode:0o700});path=join(uploads,randomUUID());await writeFile(path,binary,{mode:0o600});temporaryPath=path;}
    else path=absolutePath(payload.path,"Browser upload path");
    try{
      await page.locator(selector).setInputFiles(path);const digest=await digestFile(path);context.state.power.appendBrowserEvent(record.instanceId,"upload",pageId,{path,digest:digest.sha256,sizeBytes:digest.sizeBytes,temporary:temporaryPath!==null});
      return {payload:{instanceId:record.instanceId,pageId,path,...digest,temporary:temporaryPath!==null},instanceId:record.instanceId};
    }finally{if(temporaryPath!==null)await rm(temporaryPath,{force:true});}
  }

  private show(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): QuirtPowerProviderResult {
    const record=providerInstance(context,this.providerId,payload.instanceId,"Browser identity");const live=this.#live.get(record.instanceId);
    if(live===undefined)throw new QuirtError("browser_crashed","Browser process is not live");
    return {payload:{instanceId:record.instanceId,available:record.configuration.headless===false,selectedPageId:live.selectedPageId,route:null,limitation:record.configuration.headless===false?"A later deployment checkpoint may publish an authenticated private viewer.":"Headless contexts have no live viewer."},instanceId:record.instanceId};
  }

  private async close(payload: Readonly<Record<string,unknown>>, context: QuirtPowerProviderContext): Promise<QuirtPowerProviderResult> {
    let record=providerInstance(context,this.providerId,payload.instanceId,"Browser identity");const live=this.#live.get(record.instanceId);
    record=context.state.power.putInstance({...record,state:"stopping",health:{state:"stopping"},lastProbeAt:new Date().toISOString()});
    if(live!==undefined){this.#live.delete(record.instanceId);await live.context.close().catch(()=>{});}
    record=context.state.power.putInstance({...record,state:"stopped",health:{state:"stopped",persistentStoragePreserved:true},cleanupStatus:"complete",lastProbeAt:new Date().toISOString()});context.state.power.appendEvent(record.instanceId,"cleanup.complete",{persistentStoragePreserved:true});
    return {payload:{browser:publicProviderInstance(record)},instanceId:record.instanceId};
  }
}
