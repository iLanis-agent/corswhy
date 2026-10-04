(function (root) {
  'use strict';
  var SAFE_METHODS = ['GET', 'HEAD', 'POST'];
  var CT_OK = ['application/x-www-form-urlencoded', 'multipart/form-data', 'text/plain'];

  // header lists are arrays of [name, value]
  function lc(s) { return String(s).toLowerCase(); }
  function trim(s) { return String(s).replace(/^[ \t]+|[ \t]+$/g, ''); }
  function hasUnsafeByte(v) {
    for (var i = 0; i < v.length; i++) {
      var c = v.charCodeAt(i);
      if (c < 0x20 && c !== 0x09) return true;
      if ('"():<>?@[\\]{}'.indexOf(v[i]) >= 0 || c === 0x7f) return true;
    }
    return false;
  }
  function isRangeSimple(v) { var m = /^bytes=(\d+)-(\d*)$/.exec(v); if (!m) return false; return m[2] === '' || Number(m[2]) >= Number(m[1]); }
  // Fetch standard: "CORS-safelisted request-header" (name, value). Returns '' if safelisted, else the reason.
  function unsafeReason(name, value) {
    var n = lc(name);
    if (value.length > 128) return 'value longer than 128 bytes';
    if (n === 'accept') return hasUnsafeByte(value) ? 'Accept value has a CORS-unsafe byte' : '';
    if (n === 'accept-language' || n === 'content-language') return /^[0-9A-Za-z *,\-.;=]*$/.test(value) ? '' : name + ' value has a character outside the safelist';
    if (n === 'content-type') {
      if (hasUnsafeByte(value)) return 'Content-Type has a CORS-unsafe byte';
      var essence = lc(trim(value.split(';')[0]));
      return CT_OK.indexOf(essence) >= 0 ? '' : 'Content-Type ' + (essence || '(empty)') + ' is not form-urlencoded, multipart/form-data or text/plain';
    }
    if (n === 'range') return isRangeSimple(value) ? '' : 'Range is not a single bytes=start- or bytes=start-end range';
    return 'not a CORS-safelisted header';
  }
  // Which parts of the request force a preflight
  function preflightReasons(method, headers) {
    var reasons = [], unsafeNames = [], size = 0, safeNames = [];
    if (SAFE_METHODS.indexOf(method) < 0) reasons.push('method ' + method + ' is not GET, HEAD or POST');
    headers.forEach(function (h) {
      var r = unsafeReason(h[0], h[1]);
      if (r) { unsafeNames.push(lc(h[0])); reasons.push('header ' + h[0] + ': ' + r); }
      else { safeNames.push(lc(h[0])); size += h[1].length; }
    });
    if (size > 1024) safeNames.forEach(function (n) { unsafeNames.push(n); reasons.push('header ' + n + ': combined safelisted values exceed 1024 bytes'); });
    var seen = {}, names = [];
    unsafeNames.forEach(function (n) { if (!seen[n]) { seen[n] = 1; names.push(n); } });
    return { needed: reasons.length > 0, reasons: reasons, unsafeNames: names.sort() };
  }
  function getHeader(headers, name) { // all values joined as the browser would see them
    var out = [];
    headers.forEach(function (h) { if (lc(h[0]) === lc(name)) out.push(h[1]); });
    return out.length ? out.join(', ') : null;
  }
  function tokens(v) { return v === null ? [] : v.split(',').map(trim).filter(function (x) { return x !== ''; }); }
  function step(ok, title, detail, fix) { return { ok: ok, title: title, detail: detail, fix: ok ? '' : (fix || '') }; }

  function checkOrigin(headers, origin, creds, label) {
    var v = getHeader(headers, 'Access-Control-Allow-Origin');
    if (v === null) return step(false, label + ': Access-Control-Allow-Origin', 'header missing', 'Access-Control-Allow-Origin: ' + (creds ? origin : origin));
    if (v.indexOf(',') >= 0) return step(false, label + ': Access-Control-Allow-Origin', 'has several values (' + v + '); it must be a single origin or *', 'Access-Control-Allow-Origin: ' + origin);
    if (v === '*') {
      if (creds) return step(false, label + ': Access-Control-Allow-Origin', '* is not allowed when the request includes credentials', 'Access-Control-Allow-Origin: ' + origin);
      return step(true, label + ': Access-Control-Allow-Origin', '* allows any origin (no credentials)');
    }
    if (v === origin) return step(true, label + ': Access-Control-Allow-Origin', 'matches ' + origin);
    return step(false, label + ': Access-Control-Allow-Origin', 'is ' + v + ' but the page origin is ' + origin, 'Access-Control-Allow-Origin: ' + origin);
  }
  function checkCreds(headers, creds, label) {
    if (!creds) return null;
    var v = getHeader(headers, 'Access-Control-Allow-Credentials');
    return v === 'true' ? step(true, label + ': Access-Control-Allow-Credentials', 'true') : step(false, label + ': Access-Control-Allow-Credentials', v === null ? 'header missing but the request includes credentials' : 'is "' + v + '", it must be exactly true', 'Access-Control-Allow-Credentials: true');
  }

  // req: {origin, method, headers, credentials}; pre: {status, headers} | null; res: {headers}
  function analyze(req, pre, res) {
    var method = req.method, headers = req.headers, creds = !!req.credentials, origin = req.origin;
    var pf = preflightReasons(method, headers), steps = [];
    if (pf.needed) {
      if (!pre) steps.push(step(false, 'Preflight response', 'none given', 'Answer the OPTIONS request with a 2xx status and the CORS headers below'));
      else {
        steps.push(step(pre.status >= 200 && pre.status <= 299, 'Preflight: status', 'OPTIONS returned ' + pre.status, 'Return 200 or 204 to OPTIONS, without redirecting'));
        steps.push(checkOrigin(pre.headers, origin, creds, 'Preflight'));
        var c = checkCreds(pre.headers, creds, 'Preflight'); if (c) steps.push(c);
        var am = tokens(getHeader(pre.headers, 'Access-Control-Allow-Methods'));
        var mOk = SAFE_METHODS.indexOf(method) >= 0 || am.indexOf(method) >= 0 || (!creds && am.indexOf('*') >= 0);
        var mWhy = SAFE_METHODS.indexOf(method) >= 0 ? method + ' is always allowed (CORS-safelisted method)' : am.indexOf(method) >= 0 ? method + ' is listed' : (!creds && am.indexOf('*') >= 0) ? '* allows every method (no credentials)' : method + ' is not listed' + (creds && am.indexOf('*') >= 0 ? ' (* does not count with credentials)' : '');
        steps.push(step(mOk, 'Preflight: Access-Control-Allow-Methods', mWhy, 'Access-Control-Allow-Methods: ' + (am.length ? am.join(', ') + ', ' : '') + method));
        if (pf.unsafeNames.length) {
          var ah = tokens(getHeader(pre.headers, 'Access-Control-Allow-Headers')).map(lc);
          var wild = !creds && ah.indexOf('*') >= 0;
          var missing = pf.unsafeNames.filter(function (n) { return !(ah.indexOf(n) >= 0 || (wild && n !== 'authorization')); });
          var why = missing.length ? 'not allowed: ' + missing.join(', ') + (missing.indexOf('authorization') >= 0 && ah.indexOf('*') >= 0 ? ' (* never covers Authorization)' : (creds && ah.indexOf('*') >= 0 ? ' (* does not count with credentials)' : '')) : 'all of ' + pf.unsafeNames.join(', ') + ' allowed';
          steps.push(step(missing.length === 0, 'Preflight: Access-Control-Allow-Headers', why, 'Access-Control-Allow-Headers: ' + ah.concat(missing.filter(function (n) { return ah.indexOf(n) < 0; })).join(', ')));
        }
      }
    }
    if (!res) steps.push(step(false, 'Actual response', 'none given', 'Add the CORS headers to the real response too'));
    else {
      steps.push(checkOrigin(res.headers, origin, creds, 'Response'));
      var c2 = checkCreds(res.headers, creds, 'Response'); if (c2) steps.push(c2);
    }
    var firstBad = null; steps.forEach(function (s) { if (!s.ok && !firstBad) firstBad = s; });
    var warnings = [];
    var hv = (pre && pre.headers) || [], rv = (res && res.headers) || [];
    [hv, rv].forEach(function (h) {
      var o = getHeader(h, 'Access-Control-Allow-Origin');
      if (o && o !== '*' && tokens(getHeader(h, 'Vary')).map(lc).indexOf('origin') < 0 && warnings.indexOf('Vary: Origin missing') < 0) warnings.push('Vary: Origin missing');
      if (o === 'null' && warnings.indexOf('ACAO null') < 0) warnings.push('ACAO null');
    });
    return { preflight: pf, steps: steps, allowed: !firstBad, blockedAt: firstBad ? firstBad.title : null, warnings: warnings };
  }
  function parseHeaderLines(text) {
    var out = [], bad = [];
    String(text).split(/\r?\n/).forEach(function (line, i) {
      if (trim(line) === '') return;
      var k = line.indexOf(':');
      if (k <= 0 || !/^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/.test(trim(line.slice(0, k)))) { bad.push(i + 1); return; }
      out.push([trim(line.slice(0, k)), trim(line.slice(k + 1))]);
    });
    return { headers: out, bad: bad };
  }
  var api = { analyze: analyze, preflightReasons: preflightReasons, unsafeReason: unsafeReason, parseHeaderLines: parseHeaderLines, getHeader: getHeader, tokens: tokens };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.CorsWhy = api;
})(typeof window !== 'undefined' ? window : this);
