package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
	"golang.org/x/sys/windows/svc"
)

var (
	stateMu    sync.Mutex
	curRules   Rules
	enforcing  bool // true quando há bloqueio ativo (regras ligadas e sem liberação)
)

// ---------------- serviço ----------------
type service struct{}

func (m *service) Execute(args []string, r <-chan svc.ChangeRequest, s chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown
	s <- svc.Status{State: svc.StartPending}
	stop := make(chan struct{})
	go runLoop(stop)
	s <- svc.Status{State: svc.Running, Accepts: accepted}
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			s <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s <- svc.Status{State: svc.StopPending}
			close(stop)
			revertAll() // ao parar o serviço, desfaz tudo
			s <- svc.Status{State: svc.Stopped}
			return false, 0
		}
	}
	return false, 0
}

func runOnce() {
	c, err := loadConfig()
	if err != nil {
		fmt.Println("sem configuração:", err)
		return
	}
	if c.EnrollToken != "" && c.DeviceID == "" {
		if err := enroll(c); err != nil {
			fmt.Println("enroll:", err)
			return
		}
	}
	sc, err := fetchConfig(c)
	if err != nil {
		fmt.Println("config:", err)
		return
	}
	applyFromServer(sc)
	fmt.Printf("aplicado: active=%v release=%v install=%v sites=%v adult=%v\n",
		sc.Active, sc.Release, sc.Rules.BlockInstall, sc.Rules.BlockSites, sc.Rules.AdultBlock)
	report(c)
}

func runLoop(stop <-chan struct{}) {
	defer func() { _ = recover() }()
	guard := time.NewTicker(3 * time.Second) // vigia de processos
	poll := time.NewTicker(30 * time.Second) // conversa com o servidor
	defer guard.Stop()
	defer poll.Stop()
	pollNow(true)
	for {
		select {
		case <-stop:
			return
		case <-guard.C:
			func() { defer func() { _ = recover() }(); guardProcesses() }()
		case <-poll.C:
			pollNow(false)
		}
	}
}

func pollNow(first bool) {
	defer func() { _ = recover() }()
	c, err := loadConfig()
	if err != nil {
		if first {
			logf("ainda sem configuração — nada é bloqueado (fail-open)")
		}
		return
	}
	if c.EnrollToken != "" && c.DeviceID == "" {
		if err := enroll(c); err != nil {
			logf("enroll falhou: %v", err)
		} else {
			logf("registrado no painel: device=%s", c.DeviceID)
		}
	}
	if c.DeviceID == "" {
		return
	}
	sc, err := fetchConfig(c)
	if err != nil {
		if cached := loadCache(); cached != nil {
			logf("servidor indisponível (%v) — usando última configuração salva", err)
			applyFromServer(cached)
		} else {
			logf("servidor indisponível e sem cache — nada é bloqueado (fail-open)")
		}
		return
	}
	saveCache(sc)
	applyFromServer(sc)
	report(c)
}

// decide entre aplicar as regras ou suspender (liberação temporária / regras desligadas)
func applyFromServer(sc *ServerConfig) {
	defer func() { _ = recover() }()
	releaseActive := sc.Release > 0 && sc.Release > time.Now().UnixMilli()
	if !sc.Active || releaseActive {
		stateMu.Lock()
		enforcing = false
		curRules = sc.Rules
		stateMu.Unlock()
		revertAll()
		if releaseActive {
			logf("liberação temporária ativa — bloqueio suspenso")
		}
		return
	}
	stateMu.Lock()
	curRules = sc.Rules
	enforcing = true
	stateMu.Unlock()
	applySites(sc.Rules)
	applyDNS(sc.Rules.AdultBlock)
	applyBrowserPolicy(sc.Rules)
}

func revertAll() {
	defer func() { _ = recover() }()
	writeHostsBlock(nil)
	applyDNS(false)
	clearBrowserPolicy()
}

// ---------------- bloqueio de sites (arquivo hosts) ----------------
func hostsFile() string {
	w := os.Getenv("SystemRoot")
	if w == "" {
		w = `C:\Windows`
	}
	return filepath.Join(w, "System32", "drivers", "etc", "hosts")
}

func applySites(r Rules) {
	if !r.BlockSites || r.SitesMode != "block" {
		// modo "só liberar estes" é aplicado pela política do navegador; hosts fica limpo
		writeHostsBlock(nil)
		return
	}
	var domains []string
	for _, d := range r.SitesList {
		domains = append(domains, cleanDomain(d))
	}
	writeHostsBlock(domains)
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	d = strings.TrimPrefix(d, "www.")
	if i := strings.IndexAny(d, "/:"); i >= 0 {
		d = d[:i]
	}
	return d
}

func writeHostsBlock(domains []string) {
	path := hostsFile()
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	content := string(b)
	// remove bloco antigo
	if i := strings.Index(content, hostsBegin); i >= 0 {
		if j := strings.Index(content, hostsEnd); j >= 0 && j > i {
			content = content[:i] + content[j+len(hostsEnd):]
		}
	}
	content = strings.TrimRight(content, "\r\n")
	if len(domains) > 0 {
		var sb strings.Builder
		sb.WriteString("\r\n" + hostsBegin + "\r\n")
		for _, d := range domains {
			if d == "" {
				continue
			}
			sb.WriteString("0.0.0.0 " + d + "\r\n")
			sb.WriteString("0.0.0.0 www." + d + "\r\n")
		}
		sb.WriteString(hostsEnd + "\r\n")
		content += sb.String()
	} else {
		content += "\r\n"
	}
	_ = os.WriteFile(path, []byte(content), 0644)
	_ = exec.Command("ipconfig", "/flushdns").Run()
}

// ---------------- DNS com filtro família (conteúdo adulto) ----------------
func listInterfaces() []string {
	out, err := exec.Command("netsh", "interface", "ipv4", "show", "interfaces").Output()
	if err != nil {
		return nil
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && (f[2] == "connected" || f[2] == "conectado") {
			name := strings.TrimSpace(strings.Join(f[4:], " "))
			if name != "" && !strings.EqualFold(name, "Loopback Pseudo-Interface 1") {
				names = append(names, name)
			}
		}
	}
	return names
}

var dnsApplied bool

func applyDNS(adult bool) {
	if adult {
		for _, n := range listInterfaces() {
			_ = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers", "name="+n, "static", familyDNS1, "primary").Run()
			_ = exec.Command("netsh", "interface", "ipv4", "add", "dnsservers", "name="+n, familyDNS2, "index=2").Run()
		}
		dnsApplied = true
	} else if dnsApplied {
		for _, n := range listInterfaces() {
			_ = exec.Command("netsh", "interface", "ipv4", "set", "dnsservers", "name="+n, "dhcp").Run()
		}
		dnsApplied = false
	}
	_ = exec.Command("ipconfig", "/flushdns").Run()
}

// ---------------- política de navegador (Chrome/Edge/Brave) ----------------
var browserPolicyKeys = []string{
	`SOFTWARE\Policies\Google\Chrome`,
	`SOFTWARE\Policies\Microsoft\Edge`,
	`SOFTWARE\Policies\BraveSoftware\Brave`,
}

func applyBrowserPolicy(r Rules) {
	if !r.BlockSites {
		clearBrowserPolicy()
		return
	}
	var block, allow []string
	if r.SitesMode == "allow" {
		block = []string{"*"}
		allow = append([]string{}, r.SitesList...)
		// garante o essencial para não travar o Windows/painel
		allow = append(allow, "painel-remoto.link-br.site", "remoto.link-br.site", "microsoft.com", "windowsupdate.com", "gov.br")
	} else {
		block = append([]string{}, r.SitesList...)
	}
	for _, base := range browserPolicyKeys {
		setListPolicy(base+`\URLBlocklist`, block)
		setListPolicy(base+`\URLAllowlist`, allow)
		if k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, base, registry.SET_VALUE); err == nil {
			_ = k.SetDWordValue("IncognitoModeAvailability", 1) // desliga aba anônima
			k.Close()
		}
	}
}

func setListPolicy(path string, items []string) {
	_ = registry.DeleteKey(registry.LOCAL_MACHINE, path)
	if len(items) == 0 {
		return
	}
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, path, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()
	for i, v := range items {
		_ = k.SetStringValue(fmt.Sprintf("%d", i+1), v)
	}
}

func clearBrowserPolicy() {
	for _, base := range browserPolicyKeys {
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, base+`\URLBlocklist`)
		_ = registry.DeleteKey(registry.LOCAL_MACHINE, base+`\URLAllowlist`)
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.SET_VALUE); err == nil {
			_ = k.DeleteValue("IncognitoModeAvailability")
			k.Close()
		}
	}
}

// ---------------- bloqueio de instalação (vigia de processos) ----------------
var userWritableHints = []string{`\downloads\`, `\temp\`, `\appdata\local\temp\`, `\desktop\`, `\appdata\local\programs\`}
var installerHints = []string{"setup", "install", "instalad", "_setup", "-setup", "websetup", "inno", "nsis"}

func guardProcesses() {
	stateMu.Lock()
	r := curRules
	on := enforcing
	stateMu.Unlock()
	if !on || !r.BlockInstall {
		return
	}
	allow := map[string]bool{}
	for _, a := range r.InstallAllow {
		allow[strings.ToLower(strings.TrimSpace(a))] = true
	}
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if windows.Process32First(snap, &pe) != nil {
		return
	}
	for {
		exe := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))
		pid := pe.ProcessID
		if exe != "" && !neverKill[exe] && !allow[exe] {
			full := fullPath(pid)
			lf := strings.ToLower(full)
			trusted := strings.HasPrefix(lf, `c:\windows\`) ||
				strings.Contains(lf, `\program files\`) || strings.Contains(lf, `\program files (x86)\`)
			if !trusted {
				suspicious := false
				for _, h := range installerHints {
					if strings.Contains(exe, h) {
						suspicious = true
						break
					}
				}
				if !suspicious {
					for _, h := range userWritableHints {
						if strings.Contains(lf, h) {
							suspicious = true
							break
						}
					}
				}
				if suspicious {
					if killPID(pid) {
						logf("instalação bloqueada: %s (%s)", exe, full)
						addEvent("install_blocked", exe)
						notify("Instalação bloqueada", exe+" não é permitido neste computador. Fale com a ExpressChat.")
					}
				}
			}
		}
		if windows.Process32Next(snap, &pe) != nil {
			break
		}
	}
}

func fullPath(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func killPID(pid uint32) bool {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 1) == nil
}

func notify(title, msg string) {
	// aviso simples ao usuário logado, sem travar nada se falhar
	_ = exec.Command("msg", "*", "/TIME:8", title+": "+msg).Start()
}
