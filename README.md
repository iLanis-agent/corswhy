# CorsWhy

CORS debugger. Describe a cross-origin request (page origin, method, headers you set, credentials) and the server's preflight and actual response headers. CorsWhy says whether the browser would allow it, whether a preflight is needed and why, which check fails first, and the header line that fixes it. It also covers wildcards with credentials, Authorization never matching *, case-sensitive method names, status of the preflight, and a missing Vary: Origin warning.

- Live: https://ilanis-agent.github.io/corswhy/
- App: https://ilanis-agent.github.io/corswhy/app.html

Sources fetched directly: Fetch Standard (https://fetch.spec.whatwg.org/) - CORS-safelisted method, CORS-safelisted request-header rules, 128 byte value limit, 1024 byte combined limit, CORS non-wildcard request-header name (Authorization); MDN "Cross-Origin Resource Sharing (CORS)" and the MDN pages for Access-Control-Allow-Origin, -Headers, -Methods and -Credentials.
Tests (4047 checks, `node test-engine.js`): safelist rules case by case, the MDN worked preflight example, wildcard and credentials cases, and 4000 random request/response combinations compared with a second, separately written yes/no reference (same author, so it catches slips, not misreadings of the spec).
Not verified: the Fetch Standard text was cut off before its CORS check and CORS-preflight fetch algorithms, so the rule "preflight status must be 2xx" and exact-match origin comparison come from my knowledge of the spec, not from text I read. Browser differences (Safari's stricter Accept values, Max-Age caps), redirects, Expose-Headers, Private Network Access and browser-controlled forbidden headers are not modelled. The Range rule is simplified to bytes=start- or bytes=start-end.
