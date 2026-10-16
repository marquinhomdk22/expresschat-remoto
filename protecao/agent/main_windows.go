// ExpressChat Proteção — agente Windows.
// Serviço VISÍVEL e removível que aplica as regras definidas no painel:
// bloqueio de instalação, bloqueio de sites e filtro de conteúdo adulto.
//
// Segurança de projeto:
//   - fail-open: sem configuração do servidor, NÃO bloqueia nada.
//   - nunca encerra processos do sistema nem o ExpressChat Remoto/Proteção.
//   - durante uma "liberação temporária", suspende todo o bloqueio.
//   - ao desligar as regras ou desinstalar, desfaz tudo (hosts, DNS, políticas).
//   - sem captura de tela e sem coleta de conteúdo pessoal.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
)

const (
	serviceName  = "ExpressChatProtecao"
	displayName  = "ExpressChat Proteção"
	description  = "Aplica as regras de proteção definidas no painel ExpressChat (bloqueio de instalação e de sites). Gerenciado pela ExpressChat."
	defaultSrv   = "https://painel-remoto.link-br.site/ec-protecao"
	version      = "1.0.0"
	hostsBegin   = "# >>> ExpressChat Protecao >>>"
	hostsEnd     = "# <<< ExpressChat Protecao <<<"
	familyDNS1   = "208.67.222.123" // OpenDNS FamilyShield
	familyDNS2   = "208.67.220.123"
)

// processos que NUNCA podem ser encerrados
var neverKill = map[string]bool{
	"explorer.exe": true, "svchost.exe": true, "winlogon.exe": true, "csrss.exe": true,
	"services.exe": true, "lsass.exe": true, "system": true, "smss.exe": true,
	"wininit.exe": true, "dwm.exe": true, "fontdrvhost.exe": true, "ctfmon.exe": true,
	"taskhostw.exe": true, "sihost.exe": true, "runtimebroker.exe": true, "searchhost.exe": true,
	"expresschatremoto.exe": true, "expresschatprotecao.exe": true, "msiexec.exe": true,
	"rundll32.exe": true, "conhost.exe": true, "cmd.exe": true, "powershell.exe": true,
}

type Config struct {
	Server       string `json:"server"`
	EnrollToken  string `json:"enrollToken"`
	DeviceID     string `json:"deviceId"`
	Token        string `json:"token"`
	GUID         string `json:"guid"`
	UninstallKey string `json:"uninstallKey"` // senha para desinstalar pelo próprio programa
}

type Rules struct {
	BlockInstall     bool     `json:"blockInstall"`
	InstallAllow     []string `json:"installAllow"`
	BlockSites       bool     `json:"blockSites"`
	SitesMode        string   `json:"sitesMode"`
	SitesList        []string `json:"sitesList"`
	AdultBlock       bool     `json:"adultBlock"`
	ForceStandardUser bool    `json:"forceStandardUser"`
}

type ServerConfig struct {
	PollSeconds int      `json:"pollSeconds"`
	Release     int64    `json:"release"`
	Active      bool     `json:"active"`
	Rules       Rules    `json:"rules"`
	NeverKill   []string `json:"neverKill"`
}

var (
	mu          sync.Mutex
	counters    = map[string]int{}
	pendingEvts []map[string]string
)

// ------------- caminhos -------------
func dataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	d := filepath.Join(pd, "ExpressChatProtecao")
	_ = os.MkdirAll(d, 0755)
	return d
}
func cfgPath() string   { return filepath.Join(dataDir(), "config.json") }
func cachePath() string { return filepath.Join(dataDir(), "cache.json") }
func logPath() string   { return filepath.Join(dataDir(), "protecao.log") }

func logf(format string, a ...interface{}) {
	line := time.Now().Format("2006-01-02 15:04:05 ") + fmt.Sprintf(format, a...) + "\n"
	f, err := os.OpenFile(logPath(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err == nil {
		_, _ = f.WriteString(line)
		_ = f.Close()
	}
}

func loadConfig() (*Config, error) {
	b, err := os.ReadFile(cfgPath())
	if err != nil {
		return nil, err
	}
	c := &Config{}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, err
	}
	if c.Server == "" {
		c.Server = defaultSrv
	}
	return c, nil
}
func saveConfig(c *Config) error {
	b, _ := json.MarshalIndent(c, "", "  ")
	return os.WriteFile(cfgPath(), b, 0644)
}
func loadCache() *ServerConfig {
	b, err := os.ReadFile(cachePath())
	if err != nil {
		return nil
	}
	sc := &ServerConfig{}
	if json.Unmarshal(b, sc) != nil {
		return nil
	}
	return sc
}
func saveCache(sc *ServerConfig) { b, _ := json.Marshal(sc); _ = os.WriteFile(cachePath(), b, 0644) }

// ------------- comunicação com o servidor -------------
var httpc = &http.Client{Timeout: 15 * time.Second}

func enroll(c *Config) error {
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]string{
		"enrollToken": c.EnrollToken, "guid": c.GUID, "hostname": hostname,
		"peerId": readPeerID(), "agentVersion": version,
	})
	resp, err := httpc.Post(c.Server+"/agent/enroll", "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var out struct{ DeviceID, Token, Error string }
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.DeviceID == "" {
		return fmt.Errorf("enroll falhou: %s", out.Error)
	}
	c.DeviceID, c.Token = out.DeviceID, out.Token
	return saveConfig(c)
}

func fetchConfig(c *Config) (*ServerConfig, error) {
	url := fmt.Sprintf("%s/agent/config?device=%s&token=%s", c.Server, c.DeviceID, c.Token)
	resp, err := httpc.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		return nil, fmt.Errorf("401")
	}
	sc := &ServerConfig{}
	if err := json.NewDecoder(resp.Body).Decode(sc); err != nil {
		return nil, err
	}
	return sc, nil
}

func report(c *Config) {
	mu.Lock()
	evts := pendingEvts
	pendingEvts = nil
	ct := map[string]int{"installsBlockedToday": counters["install"], "sitesBlockedToday": counters["site"]}
	mu.Unlock()
	hostname, _ := os.Hostname()
	body, _ := json.Marshal(map[string]interface{}{
		"device": c.DeviceID, "token": c.Token, "hostname": hostname, "peerId": readPeerID(),
		"agentVersion": version, "counters": ct, "events": evts,
	})
	resp, err := httpc.Post(c.Server+"/agent/report", "application/json", bytes.NewReader(body))
	if err == nil {
		resp.Body.Close()
	}
}

func addEvent(typ, detail string) {
	mu.Lock()
	defer mu.Unlock()
	if typ == "install_blocked" {
		counters["install"]++
	} else if typ == "site_blocked" {
		counters["site"]++
	}
	pendingEvts = append(pendingEvts, map[string]string{"type": typ, "detail": detail})
	if len(pendingEvts) > 100 {
		pendingEvts = pendingEvts[len(pendingEvts)-100:]
	}
}

// lê o ID do RustDesk/ExpressChat Remoto, se instalado (só para vincular no painel)
func readPeerID() string {
	for _, p := range []string{
		filepath.Join(os.Getenv("ProgramData"), "RustDesk", "config", "RustDesk.toml"),
		filepath.Join(os.Getenv("APPDATA"), "ExpressChatRemoto", "config", "ExpressChatRemoto.toml"),
	} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "id =") || strings.HasPrefix(line, "id=") {
				v := strings.Trim(strings.SplitN(line, "=", 2)[1], " '\"")
				if v != "" {
					return v
				}
			}
		}
	}
	return ""
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "install":
			if err := cmdInstall(os.Args[2:]); err != nil {
				fmt.Println("erro:", err)
				os.Exit(1)
			}
			return
		case "uninstall":
			if err := cmdUninstall(os.Args[2:]); err != nil {
				fmt.Println("erro:", err)
				os.Exit(1)
			}
			return
		case "once": // depuração: aplica uma vez e sai
			runOnce()
			return
		case "version":
			fmt.Println(version)
			return
		}
	}
	isService, _ := svc.IsWindowsService()
	if isService {
		_ = svc.Run(serviceName, &service{})
		return
	}
	fmt.Println("ExpressChat Proteção", version)
	fmt.Println("Use: install | uninstall --senha=XXX | once | version")
}
