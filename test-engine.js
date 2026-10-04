'use strict';
var C = require('./engine.js'), assert = require('assert'), n = 0, fails = 0;
function ok(c, m) { n++; if (!c) { fails++; console.log('FAIL', m); } }
function eq(a, b, m) { n++; try { assert.deepStrictEqual(a, b); } catch (e) { fails++; console.log('FAIL', m, JSON.stringify(a), JSON.stringify(b)); } }
function pre(m, h) { return C.preflightReasons(m, h).needed; }
// Fetch standard safelist rules (fetched text of the spec)
eq(pre('GET', []), false, 'plain GET'); eq(pre('HEAD', [['Accept', '*/*']]), false, 'HEAD accept');
eq(pre('PUT', []), true, 'PUT'); eq(pre('DELETE', []), true, 'DELETE'); eq(pre('PATCH', []), true, 'PATCH');
eq(pre('POST', [['Content-Type', 'application/json']]), true, 'json');
eq(pre('POST', [['content-type', 'Text/Plain;charset=UTF-8']]), false, 'text/plain mixed case with charset');
eq(pre('POST', [['Content-Type', 'multipart/form-data; boundary=x']]), false, 'multipart');
eq(pre('POST', [['Content-Type', 'application/x-www-form-urlencoded']]), false, 'urlencoded');
eq(pre('POST', [['Content-Type', 'text/xml']]), true, 'text/xml');
eq(pre('GET', [['Authorization', 'Bearer x']]), true, 'authorization');
eq(pre('GET', [['X-Requested-With', 'x']]), true, 'custom header');
eq(pre('GET', [['Accept-Language', 'en-US,en;q=0.9']]), false, 'accept-language');
eq(pre('GET', [['Accept-Language', 'en_US']]), true, 'accept-language underscore');
eq(pre('GET', [['Accept', 'text/html,a{b']]), true, 'accept unsafe byte {');
eq(pre('GET', [['Range', 'bytes=256-']]), false, 'range open'); eq(pre('GET', [['Range', 'bytes=127-255']]), false, 'range closed');
eq(pre('GET', [['Range', 'bytes=-500']]), true, 'suffix range'); eq(pre('GET', [['Range', 'bytes=0-5,10-20']]), true, 'multi range'); eq(pre('GET', [['Range', 'bytes=9-3']]), true, 'backwards range');
eq(pre('GET', [['Accept', new Array(130).join('a')]]), true, 'value > 128'); eq(pre('GET', [['Accept', new Array(129).join('a')]]), false, 'value = 128');
var big = [], i; for (i = 0; i < 9; i++) big.push(['Accept', new Array(121).join('a')]);
eq(C.preflightReasons('GET', big).needed, true, 'combined > 1024 forces preflight'); eq(C.preflightReasons('GET', big.slice(0, 8)).needed, false, 'combined 960 ok');
eq(C.preflightReasons('POST', [['X-B', '1'], ['Authorization', 'x'], ['x-b', '2']]).unsafeNames, ['authorization', 'x-b'], 'unsafe names sorted unique lowercase');
// MDN worked example: POST with X-PINGOTHER and text/xml
var O = 'https://foo.example';
var mdnReq = { origin: O, method: 'POST', headers: [['X-PINGOTHER', 'pingpong'], ['Content-Type', 'text/xml; charset=UTF-8']], credentials: false };
var mdnPre = { status: 204, headers: [['Access-Control-Allow-Origin', O], ['Access-Control-Allow-Methods', 'POST, GET, OPTIONS'], ['Access-Control-Allow-Headers', 'X-PINGOTHER, Content-Type'], ['Access-Control-Max-Age', '86400']] };
var mdnRes = { headers: [['Access-Control-Allow-Origin', O], ['Vary', 'Accept-Encoding, Origin']] };
eq(C.analyze(mdnReq, mdnPre, mdnRes).allowed, true, 'MDN example allowed');
eq(C.analyze(mdnReq, { status: 200, headers: mdnPre.headers.slice(0, 2) }, mdnRes).blockedAt, 'Preflight: Access-Control-Allow-Headers', 'missing ACAH');
eq(C.analyze(mdnReq, { status: 403, headers: mdnPre.headers }, mdnRes).blockedAt, 'Preflight: status', '403 preflight');
eq(C.analyze(mdnReq, { status: 301, headers: mdnPre.headers }, mdnRes).allowed, false, '301 preflight');
// credentials and wildcards (MDN pages: Allow-Origin, Allow-Headers, Allow-Methods, Allow-Credentials)
var cr = { origin: O, method: 'GET', headers: [], credentials: true };
eq(C.analyze(cr, null, { headers: [['Access-Control-Allow-Origin', '*'], ['Access-Control-Allow-Credentials', 'true']] }).blockedAt, 'Response: Access-Control-Allow-Origin', '* with credentials');
eq(C.analyze(cr, null, { headers: [['Access-Control-Allow-Origin', O]] }).blockedAt, 'Response: Access-Control-Allow-Credentials', 'missing ACAC');
eq(C.analyze(cr, null, { headers: [['Access-Control-Allow-Origin', O], ['Access-Control-Allow-Credentials', 'True']] }).allowed, false, 'ACAC True (case) fails');
eq(C.analyze(cr, null, { headers: [['Access-Control-Allow-Origin', O], ['Access-Control-Allow-Credentials', 'true']] }).allowed, true, 'creds ok');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, null, { headers: [['Access-Control-Allow-Origin', '*']] }).allowed, true, '* no creds');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, null, { headers: [] }).allowed, false, 'no ACAO');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, null, { headers: [['Access-Control-Allow-Origin', 'https://other.example']] }).allowed, false, 'other origin');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, null, { headers: [['Access-Control-Allow-Origin', O + '/']] }).allowed, false, 'trailing slash origin fails');
var auth = { origin: O, method: 'GET', headers: [['Authorization', 'Bearer t']], credentials: false };
var base = [['Access-Control-Allow-Origin', '*']];
eq(C.analyze(auth, { status: 200, headers: base.concat([['Access-Control-Allow-Headers', '*']]) }, { headers: base }).blockedAt, 'Preflight: Access-Control-Allow-Headers', '* does not cover Authorization');
eq(C.analyze(auth, { status: 200, headers: base.concat([['Access-Control-Allow-Headers', '*, Authorization']]) }, { headers: base }).allowed, true, '*, Authorization works');
eq(C.analyze({ origin: O, method: 'PUT', headers: [], credentials: false }, { status: 200, headers: base.concat([['Access-Control-Allow-Methods', '*']]) }, { headers: base }).allowed, true, '* methods no creds');
eq(C.analyze({ origin: O, method: 'PUT', headers: [], credentials: true }, { status: 200, headers: [['Access-Control-Allow-Origin', O], ['Access-Control-Allow-Credentials', 'true'], ['Access-Control-Allow-Methods', '*']] }, { headers: [['Access-Control-Allow-Origin', O], ['Access-Control-Allow-Credentials', 'true']] }).blockedAt, 'Preflight: Access-Control-Allow-Methods', '* methods with creds');
eq(C.analyze({ origin: O, method: 'PUT', headers: [], credentials: false }, { status: 200, headers: base.concat([['Access-Control-Allow-Methods', 'put']]) }, { headers: base }).allowed, false, 'method names are case-sensitive');
eq(C.analyze({ origin: O, method: 'POST', headers: [['X-A', '1']], credentials: false }, { status: 200, headers: base.concat([['Access-Control-Allow-Headers', 'X-A']]) }, { headers: base }).allowed, true, 'POST is always allowed as a method, headers listed');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, { status: 500, headers: [] }, { headers: base }).allowed, true, 'preflight ignored when not needed');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, null, { headers: [['Access-Control-Allow-Origin', O]] }).warnings, ['Vary: Origin missing'], 'Vary warning');
eq(C.analyze({ origin: O, method: 'GET', headers: [], credentials: false }, null, { headers: [['Access-Control-Allow-Origin', O], ['Vary', 'Accept-Encoding, Origin']] }).warnings, [], 'no Vary warning');
eq(C.parseHeaderLines('A: 1\nbad line\n\nB:  x: y '), { headers: [['A', '1'], ['B', 'x: y']], bad: [2] }, 'parse lines');
// independent reference for the final yes/no, randomized
function ref(req, pre, res) {
  var M = req.method, H = req.headers, cr = req.credentials, o = req.origin;
  function g(h, k) { var v = []; h.forEach(function (x) { if (x[0].toLowerCase() === k) v.push(x[1]); }); return v.length ? v.join(', ') : null; }
  function originOk(h) { var v = g(h, 'access-control-allow-origin'); if (v === null) return false; if (v === '*') return !cr; return v === o; }
  function credOk(h) { return !cr || g(h, 'access-control-allow-credentials') === 'true'; }
  var needs = ['GET', 'HEAD', 'POST'].indexOf(M) < 0, unsafe = [];
  H.forEach(function (x) { var k = x[0].toLowerCase(); if (k === 'content-type') { if (['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'].indexOf(x[1].split(';')[0].trim().toLowerCase()) < 0) unsafe.push(k); } else if (k !== 'accept') unsafe.push(k); });
  if (unsafe.length) needs = true;
  var good = originOk(res.headers) && credOk(res.headers);
  if (needs) {
    good = good && pre.status >= 200 && pre.status < 300 && originOk(pre.headers) && credOk(pre.headers);
    var ms = (g(pre.headers, 'access-control-allow-methods') || '').split(',').map(function (s) { return s.trim(); });
    good = good && (['GET', 'HEAD', 'POST'].indexOf(M) >= 0 || ms.indexOf(M) >= 0 || (!cr && ms.indexOf('*') >= 0));
    var hs = (g(pre.headers, 'access-control-allow-headers') || '').split(',').map(function (s) { return s.trim().toLowerCase(); });
    unsafe.forEach(function (k) { good = good && (hs.indexOf(k) >= 0 || (!cr && hs.indexOf('*') >= 0 && k !== 'authorization')); });
  }
  return good;
}
var seed = 12345; function rnd(k) { seed = (seed * 1103515245 + 12345) & 0x7fffffff; return seed % k; } function pick(a) { return a[rnd(a.length)]; }
for (i = 0; i < 4000; i++) {
  var req = { origin: O, method: pick(['GET', 'POST', 'PUT', 'DELETE', 'HEAD']), credentials: rnd(2) === 1, headers: [] };
  [['Accept', '*/*'], ['Content-Type', pick(['application/json', 'text/plain', 'text/plain;charset=utf-8', 'multipart/form-data'])], ['Authorization', 'x'], ['X-Custom', '1']].forEach(function (h) { if (rnd(3) === 0) req.headers.push(h); });
  function rh() { var h = []; if (rnd(5)) h.push(['Access-Control-Allow-Origin', pick([O, O, '*', 'https://x.example'])]); if (rnd(2)) h.push(['Access-Control-Allow-Credentials', pick(['true', 'true', 'false'])]);
    if (rnd(2)) h.push(['Access-Control-Allow-Methods', pick(['*', 'PUT, DELETE', 'GET, POST', 'DELETE', 'PUT'])]); if (rnd(2)) h.push(['Access-Control-Allow-Headers', pick(['*', 'authorization, content-type', 'X-Custom, Content-Type', 'Authorization, *', 'x-custom, authorization, content-type'])]); return h; }
  var p = { status: pick([200, 204, 403, 301]), headers: rh() }, r = { headers: rh() };
  eq(C.analyze(req, p, r).allowed, ref(req, p, r), 'random ' + i);
}
console.log(n + ' checks, ' + fails + ' failures'); process.exit(fails ? 1 : 0);
