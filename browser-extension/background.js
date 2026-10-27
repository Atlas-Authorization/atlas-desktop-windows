// Reference extension for the Atlas device sign-in native host. Set the Atlas sign-in host(s) in storage as {hosts:["auth.example.com"]}
// (managed storage or the options you ship). When the browser navigates to one of them, the host is asked for a completed sign-in for
// the page being opened (redirect_to) and the tab continues there, so the user lands signed in with a device-bound session. No token ever passes through the extension.
const HOST = "net.atlasauth.device_sso";
const recent = new Map(); // tab id -> time of the last ticket, so a failed sign-in cannot loop

async function atlasHosts() {
  const { hosts } = await chrome.storage.managed.get("hosts").catch(() => ({}));
  return Array.isArray(hosts) ? hosts : [];
}

chrome.webNavigation.onBeforeNavigate.addListener(async (d) => {
  if (d.frameId !== 0) return;
  const url = new URL(d.url);
  if (!(await atlasHosts()).includes(url.hostname)) return;
  if (Date.now() - (recent.get(d.tabId) || 0) < 30000) return;
  recent.set(d.tabId, Date.now());
  chrome.runtime.sendNativeMessage(HOST, { type: "get_ticket", redirect_url: d.url }, (reply) => {
    if (chrome.runtime.lastError || !reply || !reply.ok || !reply.redirect_to) return; // not registered or sign-in needed: normal page
    const t = new URL(reply.redirect_to);
    if (t.protocol !== "https:" || t.hostname !== url.hostname) return; // only ever navigate back to the page we left
    chrome.tabs.update(d.tabId, { url: reply.redirect_to });
  });
});
