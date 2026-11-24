// MV3 spike: does an open native port keep the event page alive, and do
// proxy.onRequest and the in-memory state survive the idle timeout?
const started = Date.now();
let port = browser.runtime.connectNative("vpncell_spike");
port.postMessage({kind: "start", started});
port.onMessage.addListener((m) => port.postMessage({kind: "echo", m, started}));
port.onDisconnect.addListener(() => {});
setInterval(() => { try { port.postMessage({kind: "tick", started, t: Date.now()}); } catch (e) {} }, 5000);
browser.proxy.onRequest.addListener((d) => {
  try { port.postMessage({kind: "proxy", url: d.url, started}); } catch (e) {}
  return {type: "direct"};
}, {urls: ["<all_urls>"]});
