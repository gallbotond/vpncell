//go:build integration

package integration

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/gallbotond/vpncell/test/webdriver"
)

// The browser runs as the desktop user (in group vpncell and allowed on the
// test profiles), like a real user's Firefox.
const browserUser = "botond"

const extUUID = "5f8e2a1c-0b6d-4c3e-9a7f-2d4b6c8e0a11"
const extID = "vpncell@gallbotond.github.io"

type browserKind struct {
	name   string
	gecko  string
	binary string // empty: the driver's own Firefox (snap)
}

func browserKinds() []browserKind {
	kinds := []browserKind{}
	tb := filepath.Join(repoRoot, "test/firefox/firefox/firefox")
	if _, err := os.Stat(tb); err == nil {
		kinds = append(kinds, browserKind{"tarball", filepath.Join(repoRoot, "test/firefox/geckodriver"), tb})
	}
	if _, err := os.Stat("/snap/bin/geckodriver"); err == nil {
		kinds = append(kinds, browserKind{"snap", "/snap/bin/geckodriver", ""})
	}
	if only := os.Getenv("VPNCELL_TEST_BROWSERS"); only != "" {
		var f []browserKind
		for _, k := range kinds {
			if strings.Contains(","+only+",", ","+k.name+",") {
				f = append(f, k)
			}
		}
		kinds = f
	}
	return kinds
}

// snapPortalGranted reports whether the user allowed the snap Firefox to
// start vpncell's native host through the WebExtensions portal (a one-time
// dialog, stored in the portal permission store).
func snapPortalGranted() bool {
	out, err := run("", "runuser", "-u", browserUser, "--", "env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus",
		"gdbus", "call", "--session", "--dest", "org.freedesktop.impl.portal.PermissionStore",
		"--object-path", "/org/freedesktop/impl/portal/PermissionStore",
		"--method", "org.freedesktop.impl.portal.PermissionStore.Lookup", "webextensions", "vpncell")
	return err == nil && strings.Contains(out, "'snap.firefox': ['yes']")
}

type browser struct {
	t    *testing.T
	kind browserKind
	s    *webdriver.Session
	gd   *exec.Cmd
	main string // handle of the first tab
}

func freePort() int {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func userEnv(name string) []string {
	c := credsOf(name)
	uid := fmt.Sprint(c.uid)
	return []string{
		"HOME=" + c.home, "USER=" + name, "LOGNAME=" + name,
		"PATH=/snap/bin:/usr/local/bin:/usr/bin:/bin",
		"XDG_RUNTIME_DIR=/run/user/" + uid,
		"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + uid + "/bus",
		"MOZ_HEADLESS=1", "LANG=C.UTF-8",
	}
}

func startBrowser(t *testing.T, kind browserKind, prefs map[string]any) *browser {
	t.Helper()
	port := freePort()
	c := credsOf(browserUser)
	gd := exec.Command(kind.gecko, "--port", fmt.Sprint(port), "--allow-system-access")
	gd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: c.uid, Gid: c.gid, Groups: c.groups}, Setsid: true}
	gd.Env = userEnv(browserUser)
	gd.Dir = c.home
	logf, _ := os.Create(filepath.Join(os.TempDir(), "vpncell-geckodriver-"+kind.name+".log"))
	gd.Stdout, gd.Stderr = logf, logf
	if err := gd.Start(); err != nil {
		t.Fatalf("geckodriver: %v", err)
	}
	if kind.name == "snap" && !snapPortalGranted() {
		gd.Process.Kill()
		gd.Wait()
		t.Fatalf("KNOWN FAILURE (needs the user): the snap Firefox may not start vpncell-native yet. " +
			"The WebExtensions portal asks once, in a dialog, whether Firefox may start it; headless tests cannot answer it. " +
			"Allow it once (see README, \"Snap Firefox\"), then rerun.")
	}
	b := &browser{t: t, kind: kind, gd: gd}
	t.Cleanup(b.close)
	base := fmt.Sprintf("http://127.0.0.1:%d", port)
	waitFor(t, 20*time.Second, "geckodriver", func() bool {
		cn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			cn.Close()
		}
		return err == nil
	})
	p := map[string]any{
		"privacy.userContext.enabled":                true,
		"privacy.userContext.ui.enabled":             true,
		"extensions.webextensions.uuids":             fmt.Sprintf(`{"%s":"%s"}`, extID, extUUID),
		"browser.shell.checkDefaultBrowser":          false,
		"app.update.disabledForTesting":              true,
		"datareporting.policy.dataSubmissionEnabled": false,
		"toolkit.telemetry.reportingpolicy.firstRun": false,
		"browser.safebrowsing.malware.enabled":       false,
		"browser.safebrowsing.phishing.enabled":      false,
		"network.captive-portal-service.enabled":     false,
		"network.connectivity-service.enabled":       false,
		"extensions.getAddons.cache.enabled":         false,
		"browser.newtabpage.enabled":                 false,
		"browser.startup.page":                       0,
		// Run the extension in private windows too, to prove that private
		// windows still connect directly when it does.
		"extensions.allowPrivateBrowsingByDefault": true,
		// What `vpncell firefox-policy install` sets (README "Firefox"):
		// without it every http:// navigation in a mapped container sends
		// an HTTPS-record lookup for the hostname through the host
		// resolver. TestBrowserHTTPNameNoHostDNS checks the real system
		// configuration instead; the other browser tests use this so that
		// they test what they are about.
		"network.dns.native_https_query": false,
	}
	for k, v := range prefs {
		if v == nil {
			delete(p, k)
			continue
		}
		p[k] = v
	}
	opts := map[string]any{"args": []string{"-headless"}, "prefs": p}
	if kind.binary != "" {
		opts["binary"] = kind.binary
	}
	s, err := webdriver.New(base, opts)
	if err != nil {
		t.Fatalf("new session (%s): %v", kind.name, err)
	}
	b.s = s
	b.main, _ = s.Handle()
	xpi := filepath.Join(repoRoot, "bin/vpncell.xpi")
	if _, err := s.InstallAddon(xpi); err != nil {
		t.Fatalf("install add-on: %v", err)
	}
	// Wait until the background page has talked to the daemon.
	waitFor(t, 30*time.Second, "extension connected to the daemon", func() bool {
		st := b.popupState()
		return st != nil && st["daemonUp"] == true
	})
	return b
}

func (b *browser) close() {
	if b.s != nil {
		b.s.Close()
		b.s = nil
	}
	if b.gd != nil && b.gd.Process != nil {
		syscall.Kill(-b.gd.Process.Pid, syscall.SIGTERM)
		done := make(chan struct{})
		go func() { b.gd.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			syscall.Kill(-b.gd.Process.Pid, syscall.SIGKILL)
		}
		b.gd = nil
	}
}

// chrome runs a script in the browser's chrome (privileged) context.
func (b *browser) chrome(script string, args []any, out any) error {
	if err := b.s.SetContext("chrome"); err != nil {
		return err
	}
	defer b.s.SetContext("content")
	return b.s.Exec(script, args, out)
}

func (b *browser) chromeAsync(script string, args []any, out any) error {
	if err := b.s.SetContext("chrome"); err != nil {
		return err
	}
	defer b.s.SetContext("content")
	return b.s.ExecAsync(script, args, out)
}

// createContainer creates a Multi-Account Container and returns its
// userContextId.
func (b *browser) createContainer(name string) int {
	var id int
	err := b.chrome(`const ContextualIdentityService = (() => { for (const u of ["moz-src:///toolkit/components/contextualidentity/ContextualIdentityService.sys.mjs", "resource://gre/modules/ContextualIdentityService.sys.mjs"]) { try { return ChromeUtils.importESModule(u).ContextualIdentityService; } catch (e) {} } throw new Error("ContextualIdentityService not found"); })();
return ContextualIdentityService.create(arguments[0], "fingerprint", "blue").userContextId;`, []any{name}, &id)
	if err != nil {
		b.t.Fatalf("create container: %v", err)
	}
	return id
}

func (b *browser) removeContainer(id int) {
	b.chrome(`const ContextualIdentityService = (() => { for (const u of ["moz-src:///toolkit/components/contextualidentity/ContextualIdentityService.sys.mjs", "resource://gre/modules/ContextualIdentityService.sys.mjs"]) { try { return ChromeUtils.importESModule(u).ContextualIdentityService; } catch (e) {} } throw new Error("ContextualIdentityService not found"); })();
ContextualIdentityService.remove(arguments[0]);`, []any{id}, nil)
}

func cookieStore(id int) string { return fmt.Sprintf("firefox-container-%d", id) }

func popupURL() string { return "moz-extension://" + extUUID + "/popup.html" }

// popupState asks the background page (through the popup's messaging).
func (b *browser) popupState() map[string]any {
	h, err := b.s.NewTab()
	if err != nil {
		return nil
	}
	defer func() { b.s.CloseWindow(); b.home() }()
	b.s.SwitchTo(h)
	if err := b.s.Navigate(popupURL()); err != nil {
		return nil
	}
	var out map[string]any
	if err := b.s.ExecAsync(`const cb = arguments[arguments.length-1];
browser.runtime.sendMessage({cmd: "getState"}).then(cb, e => cb({error: String(e)}));`, nil, &out); err != nil {
		return nil
	}
	return out
}

// mapContainer selects a profile for a container in the real popup page.
func (b *browser) mapContainer(id int, profile string) {
	b.t.Helper()
	h, err := b.s.NewTab()
	if err != nil {
		b.t.Fatal(err)
	}
	defer func() { b.s.CloseWindow(); b.home() }()
	b.s.SwitchTo(h)
	if err := b.s.Navigate(popupURL()); err != nil {
		b.t.Fatal(err)
	}
	sel := fmt.Sprintf(`select[data-container="%s"] option[value="%s"]`, cookieStore(id), profile)
	var opt string
	waitFor(b.t, 15*time.Second, "popup row for container", func() bool {
		opt, err = b.s.Find(sel)
		return err == nil
	})
	if err := b.s.Click(opt); err != nil {
		// Some drivers do not click <option>; set the value like a user would.
		b.s.Exec(`const s = document.querySelector(arguments[0]); s.value = arguments[1]; s.dispatchEvent(new Event("change"));`,
			[]any{fmt.Sprintf(`select[data-container="%s"]`, cookieStore(id)), profile}, nil)
	}
	waitFor(b.t, 10*time.Second, "mapping stored", func() bool {
		st := b.popupState()
		m, _ := st["mapping"].(map[string]any)
		if profile == "" {
			_, ok := m[cookieStore(id)]
			return !ok
		}
		return m[cookieStore(id)] == profile
	})
}

type pageResult struct {
	ok   bool   // a document from the server, not an error page
	text string // body text, or the error page URI
}

// openTab opens url in a new tab of the given container (0 = default) or
// in a private window and returns the tab's WebDriver handle.
func (b *browser) openTab(userContextID int, private bool, url string) string {
	b.t.Helper()
	before, _ := b.s.Handles()
	err := b.chromeAsync(`const [uc, url, priv, cb] = arguments;
const triggeringPrincipal = Services.scriptSecurityManager.getSystemPrincipal();
(async () => {
  if (priv) {
    const w = OpenBrowserWindow({private: true});
    await new Promise(r => w.addEventListener("load", r, {once: true}));
    await new Promise(r => setTimeout(r, 500));
    w.gBrowser.selectedTab = w.gBrowser.addTab(url, {triggeringPrincipal});
  } else {
    gBrowser.addTab(url, {userContextId: uc, triggeringPrincipal});
  }
})().then(() => cb(true), e => cb(String(e)));`, []any{userContextID, url, private}, nil)
	if err != nil {
		b.t.Fatalf("open tab: %v", err)
	}
	var handle string
	waitFor(b.t, 10*time.Second, "new tab handle", func() bool {
		after, _ := b.s.Handles()
		for _, h := range after {
			found := false
			for _, o := range before {
				if o == h {
					found = true
				}
			}
			if !found {
				handle = h
				return true
			}
		}
		return false
	})
	return handle
}

// readTab waits for a tab's document and returns it.
func (b *browser) readTab(handle string, timeout time.Duration) pageResult {
	b.s.SwitchTo(handle)
	defer b.home()
	deadline := time.Now().Add(timeout)
	var last pageResult
	for time.Now().Before(deadline) {
		var r map[string]any
		err := b.s.Exec(`return {uri: document.documentURI, state: document.readyState, text: document.body ? document.body.innerText : ""};`, nil, &r)
		if err == nil {
			uri, _ := r["uri"].(string)
			text, _ := r["text"].(string)
			if strings.HasPrefix(uri, "about:neterror") || strings.HasPrefix(uri, "about:certerror") {
				return pageResult{false, uri}
			}
			if r["state"] == "complete" && uri != "about:blank" && !strings.HasPrefix(uri, "about:") {
				return pageResult{true, text}
			}
			last = pageResult{false, uri + " (" + fmt.Sprint(r["state"]) + ")"}
		}
		time.Sleep(200 * time.Millisecond)
	}
	if last.text == "" {
		last.text = "timeout"
	} else {
		last.text = "timeout: " + last.text
	}
	return last
}

func (b *browser) closeTab(handle string, private bool) {
	b.s.SwitchTo(handle)
	b.s.CloseWindow()
	if private {
		b.chrome(`for (const w of Services.wm.getEnumerator("navigator:browser")) { if (PrivateBrowsingUtils.isWindowPrivate(w)) w.close(); }`, nil, nil)
	}
	b.home()
}

// load opens url in a new tab of a container (0 = default) or a private
// window, waits for it, returns the result and closes the tab.
func (b *browser) load(userContextID int, private bool, url string, timeout time.Duration) pageResult {
	b.t.Helper()
	h := b.openTab(userContextID, private, url)
	r := b.readTab(h, timeout)
	b.closeTab(h, private)
	return r
}

// loadParallel opens all tabs first (they load at the same time), then
// reads them.
func (b *browser) loadParallel(containers []int, url string, timeout time.Duration) []pageResult {
	hs := make([]string, len(containers))
	for i, c := range containers {
		hs[i] = b.openTab(c, false, url)
	}
	out := make([]pageResult, len(containers))
	for i, h := range hs {
		out[i] = b.readTab(h, timeout)
	}
	for _, h := range hs {
		b.closeTab(h, false)
	}
	return out
}

// home switches back to the main tab (or any remaining tab if Firefox
// replaced it).
func (b *browser) home() {
	hs, _ := b.s.Handles()
	for _, h := range hs {
		if h == b.main {
			b.s.SwitchTo(h)
			return
		}
	}
	if len(hs) > 0 {
		b.main = hs[0]
		b.s.SwitchTo(hs[0])
	}
}
