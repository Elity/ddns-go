import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';

const script = readFileSync(new URL('../static/oidc.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('./writing.html', import.meta.url), 'utf8');

class Element {
  constructor(id) { this.id=id; this.value=''; this.disabled=false; this.checked=false; this.hidden=false; this.dataset={}; this.listeners={}; }
  addEventListener(type,fn) { (this.listeners[type]??=[]).push(fn); }
  async fire(type,event={}) { for (const fn of this.listeners[type]??[]) await fn({currentTarget:this,target:this,preventDefault(){},...event}); }
  click() { if (!this.disabled) return this.fire('click'); }
  type(value) { if (!this.disabled) {this.value=value; return this.fire('input');} }
}

function setup(fetch) {
  const ids=['OIDCCallback','OIDCRedirectURL','OIDCScopes','OIDCAutoLogin','OIDCEnabled','OIDCIssuer','OIDCClientID','OIDCClientSecret','formGlobal','oidc-panel','saveOIDC','oidcStatus'];
  const elements=Object.fromEntries(ids.map(id=>[id,new Element(id)]));
  elements.OIDCCallback.dataset.configured='https://app.example/oidc/callback';
  const fields=ids.filter(id=>/^OIDC/.test(id)&&id!=='OIDCCallback').map(id=>elements[id]);
  const globalSave=new Element('globalSave');
  const document={getElementById:id=>elements[id],querySelector:()=>globalSave,querySelectorAll:selector=>selector.includes('[role=')?[]:fields};
  vm.runInNewContext(script,{document,location:{hash:'',origin:'https://app.example'},fetch,i18n:key=>key});
  return {elements,fields,globalSave};
}

test('pending save locks inputs; a subsequent edit is included in the next save', async()=>{
  let release;const bodies=[];
  const {elements:e,fields}=setup((url,options)=>{bodies.push(JSON.parse(options.body));return new Promise(resolve=>{release=()=>resolve({ok:true,json:async()=>({})});});});
  await e.OIDCScopes.type('openid profile');
  await e.OIDCClientSecret.type('first-secret');
  const saving=e.saveOIDC.click();
  assert.ok(fields.every(field=>field.disabled));
  await e.OIDCScopes.type('ignored-during-save');
  await e.OIDCClientSecret.type('ignored-secret');
  assert.equal(e.OIDCScopes.value,'openid profile');
  release();await saving;
  assert.ok(fields.every(field=>!field.disabled));
  assert.equal(e.OIDCClientSecret.value,'');
  await e.OIDCScopes.type('openid email');
  await e.OIDCClientSecret.type('second-secret');
  const second=e.saveOIDC.click();release();await second;
  assert.equal(bodies[1].Scopes,'openid email');
  assert.equal(bodies[1].ClientSecret,'second-secret');
});

test('failed save restores controls and preserves pending values',async()=>{
  const {elements:e,fields}=setup(async()=>({ok:false,status:500,text:async()=>'failed'}));
  await e.OIDCClientSecret.type('retry-secret');
  await e.saveOIDC.click();
  assert.equal(e.OIDCClientSecret.value,'retry-secret');
  assert.ok(fields.every(field=>!field.disabled));
});

test('Enter in OIDC text inputs saves OIDC, with no implicit webhook submit',async()=>{
  const {elements:e}=setup(async()=>({ok:true,json:async()=>({})}));
  let count=0,prevented=false;e.saveOIDC.listeners.click=[()=>{count++;}];
  await e['oidc-panel'].fire('keydown',{key:'Enter',isComposing:false,target:{matches:()=>true},preventDefault(){prevented=true;}});
  assert.equal(count,1);assert.equal(prevented,true);
  await e['oidc-panel'].fire('keydown',{key:'Enter',isComposing:true,target:{matches:()=>true}});
  assert.equal(count,1);
  const webhook=html.match(/<button[^>]*id="webhookTestBtn"[^>]*>/)[0];
  assert.match(webhook,/type="button"/);
});

test('both global Save buttons retain DNS/global semantics on the OIDC tab',async()=>{
  const start=html.indexOf('document.querySelectorAll(".submit_btn").forEach');
  const end=html.indexOf('// 切换配置项',start);
  const buttons=[new Element('topSave'),new Element('bottomSave')];const requests=[];let oidcSaves=0;
  const context={document:{querySelectorAll:()=>buttons,getElementById:id=>id==='oidc-panel'?{hidden:false}:{click(){oidcSaves++;}}},
    dnsConf:[{DnsName:'test',Name:'changed-dns'}],configIndex:0,DNS_PROVIDERS:{test:{idLabel:'id'}},globalConf:{WebhookURL:'https://hooks.example/new'},
    request:{post:async(url,body)=>{requests.push({url,body});return {result:'ok',dnsConf:[]};}},showMessage(){},i18n(){},reloadConf(){},alert(message){throw new Error(message);}};
  vm.runInNewContext(html.slice(start,end),context);
  for(const button of buttons) await button.click();
  assert.equal(oidcSaves,0);assert.equal(requests.length,2);
  assert.ok(requests.every(r=>r.url==='./save'&&r.body.WebhookURL==='https://hooks.example/new'&&r.body.DnsConf[0].Name==='changed-dns'));
});
