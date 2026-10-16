package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func argMap(args []string) map[string]string {
	m := map[string]string{}
	for _, a := range args {
		a = strings.TrimPrefix(a, "--")
		if i := strings.Index(a, "="); i >= 0 {
			m[strings.ToLower(a[:i])] = a[i+1:]
		} else {
			m[strings.ToLower(a)] = "1"
		}
	}
	return m
}

func newGUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// install: grava a configuração, registra e inicia o serviço.
// flags: --server= --enroll= --senha=
func cmdInstall(args []string) error {
	a := argMap(args)
	c, _ := loadConfig()
	if c == nil {
		c = &Config{}
	}
	if v := a["server"]; v != "" {
		c.Server = v
	}
	if c.Server == "" {
		c.Server = defaultSrv
	}
	if v := a["enroll"]; v != "" {
		c.EnrollToken = v
	}
	if v := a["senha"]; v != "" {
		c.UninstallKey = v
	}
	if c.GUID == "" {
		c.GUID = newGUID()
	}
	if err := saveConfig(c); err != nil {
		return err
	}

	exe, err := os.Executable()
	if err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	if s, err := m.OpenService(serviceName); err == nil {
		s.Close() // já existe
	} else {
		s, err := m.CreateService(serviceName, exe, mgr.Config{
			DisplayName:  displayName,
			Description:  description,
			StartType:    mgr.StartAutomatic,
			ErrorControl: mgr.ErrorNormal,
		})
		if err != nil {
			return err
		}
		defer s.Close()
	}
	// (re)inicia
	if s, err := m.OpenService(serviceName); err == nil {
		defer s.Close()
		_ = s.Start()
	}
	fmt.Println("ExpressChat Proteção instalado e iniciado.")
	return nil
}

// uninstall: exige --senha igual à cadastrada, OU --from-installer (chamado pelo desinstalador, já elevado).
func cmdUninstall(args []string) error {
	a := argMap(args)
	c, _ := loadConfig()
	if a["from-installer"] == "" {
		if c == nil || c.UninstallKey == "" {
			return fmt.Errorf("sem senha cadastrada; use o desinstalador em Aplicativos do Windows")
		}
		if a["senha"] != c.UninstallKey {
			return fmt.Errorf("senha incorreta")
		}
	}
	revertAll() // desfaz hosts/DNS/políticas antes de sair
	m, err := mgr.Connect()
	if err == nil {
		defer m.Disconnect()
		if s, err := m.OpenService(serviceName); err == nil {
			_ = controlStop(s)
			_ = s.Delete()
			s.Close()
		}
	}
	_ = os.RemoveAll(dataDir())
	fmt.Println("ExpressChat Proteção removido.")
	return nil
}

func controlStop(s *mgr.Service) error {
	st, err := s.Control(svc.Stop)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(10 * time.Second)
	for st.State != svc.Stopped {
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(300 * time.Millisecond)
		st, _ = s.Query()
	}
	return nil
}
