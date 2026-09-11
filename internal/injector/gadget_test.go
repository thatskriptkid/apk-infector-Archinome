package injector

import (
	"encoding/json"
	"testing"
)

// Конфиг gadget'а — единственное, что заставляет библиотеку поднять порт: с
// битым JSON Frida молча уходит в дефолт, а тот на Android 17 не слушает вовсе.
func TestFridaGadgetConfigIsValidAndListens(t *testing.T) {
	var cfg struct {
		Interaction struct {
			Type           string `json:"type"`
			Address        string `json:"address"`
			Port           int    `json:"port"`
			OnPortConflict string `json:"on_port_conflict"`
			OnLoad         string `json:"on_load"`
		} `json:"interaction"`
	}
	if err := json.Unmarshal(fridaGadgetConfig(), &cfg); err != nil {
		t.Fatalf("конфиг gadget'а не парсится как JSON: %v", err)
	}
	if cfg.Interaction.Type != "listen" {
		t.Errorf("interaction.type = %q, ожидался listen", cfg.Interaction.Type)
	}
	if cfg.Interaction.Port != 27042 || cfg.Interaction.Address != "127.0.0.1" {
		t.Errorf("адрес/порт = %s:%d, ожидались 127.0.0.1:27042",
			cfg.Interaction.Address, cfg.Interaction.Port)
	}
	// wait блокирует старт хоста до подключения и на Android приводит к ANR.
	if cfg.Interaction.OnLoad != "resume" {
		t.Errorf("on_load = %q, ожидался resume", cfg.Interaction.OnLoad)
	}
}

func TestSelectGadgetsFollowsHostABIs(t *testing.T) {
	got := func(names []string) []string {
		var abis []string
		for _, g := range selectGadgets(names) {
			abis = append(abis, g.abi)
		}
		return abis
	}

	if v := got([]string{"AndroidManifest.xml", "classes.dex", "lib/arm64-v8a/libfoo.so"}); len(v) != 1 || v[0] != "arm64-v8a" {
		t.Errorf("хост с lib/arm64-v8a: получено %v", v)
	}
	if v := got([]string{"lib/x86_64/libfoo.so", "lib/arm64-v8a/libfoo.so"}); len(v) != 2 {
		t.Errorf("два ABI хоста: получено %v", v)
	}
	// Чисто-Java хост: разумный минимум — мобильные ABI, а не все четыре
	// (лишние ~25 МБ STORED на каждую архитектуру).
	if v := got([]string{"AndroidManifest.xml", "classes.dex"}); len(v) != 2 || v[0] != "arm64-v8a" || v[1] != "armeabi-v7a" {
		t.Errorf("хост без lib/: получено %v", v)
	}
}
