// ==UserScript==
// @name         GlobalProtect clientless: keep site redirects inside the proxy
// @description  Edit the two @match lines to your portal address. Sites that do window.location.href="/#/..." escape the clientless rewriter and land on the portal root.
//               This catches those navigations and sends them back under /https/<host>/.
// @match        https://yourname.duckdns.org/https/*
// @match        https://yourname.duckdns.org/http/*
// @run-at       document-start
// @grant        none
// ==/UserScript==
(() => {
  const m = location.pathname.match(/^\/(https?)\/([^/]+)\//);
  if (!m || !window.navigation) return;
  const prefix = `/${m[1]}/${m[2]}`;

  navigation.addEventListener('navigate', (e) => {
    const dest = new URL(e.destination.url);
    // Anything on the portal host that isn't already proxied or portal UI is a rewrite miss
    const escaped = dest.origin === location.origin &&
      !/^\/(https?|global-protect)\//.test(dest.pathname);
    if (escaped && e.cancelable) {
      e.preventDefault();
      location.assign(prefix + dest.pathname + dest.search + dest.hash);
    }
  });
})();
