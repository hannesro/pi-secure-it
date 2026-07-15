function hostnameOf(url){ try { return new URL(url).hostname.toLowerCase(); } catch { return null; } }
function domainMatches(host,pattern){
  const p = pattern.toLowerCase();
  if (p.startsWith('*.')){ const suf = p.slice(1); return host===p.slice(2)||host.endsWith(suf); }
  return host===p;
}
function isAllowed(url,allow,deny){
  const h=hostnameOf(url); if(h===null) return 'invalid url';
  if (deny.some(p=>domainMatches(h,p))) return 'denied';
  if (allow.length===0) return null;
  if (allow.some(p=>domainMatches(h,p))) return null;
  return 'not in allowlist';
}
const allow=['github.com','*.github.com','api.github.com','npmjs.org','*.npmjs.org'];
const cases = [
  ['https://api.github.com/x', null],
  ['https://github.com', null],
  ['https://raw.githubusercontent.com/x', 'not in allowlist'],
  ['https://docs.github.com/x', null],
  ['https://example.com', 'not in allowlist'],
  ['https://evil-github.com', 'not in allowlist'],
  ['https://registry.npmjs.org', null],
  ['not-a-url', 'invalid url'],
];
let p=0,f=0;
for (const [u,exp] of cases){
  const got = isAllowed(u,allow,[]);
  const ok = got===exp;
  console.log((ok?'PASS':'FAIL')+': '+u+' → '+got+' (exp '+exp+')');
  ok?p++:f++;
}
console.log('---','PASS='+p,'FAIL='+f);
process.exit(f?1:0);
