// Package deaddrop reads the blockchain dead drops a campaign's loaders
// resolve at run time: NullReceiver wallets on Ethereum, TRON memo indexes
// pointing to BSC transactions, and the BSC account that writes them.
//
// Everything comes from public chain APIs (Blockscout, TronGrid, a BSC
// JSON-RPC node). Nothing touches the operator's servers, and stages are
// never fetched or decrypted: the report carries addresses, transaction
// hashes and timestamps only.
package deaddrop

import (
	"embed"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed builtin/*.yaml
var builtin embed.FS

// Config is what to watch.
type Config struct {
	Name         string  `yaml:"name"`
	NullReceiver []Watch `yaml:"nullreceiver"`
	// BSCIndexes are Ethereum wallets whose recipient addresses point to a
	// BSC transaction: bytes 0-3 are a block number, byte 4 the index of the
	// transaction in that block.
	BSCIndexes  []Watch     `yaml:"bsc_indexes"`
	TronIndexes []Watch     `yaml:"tron_indexes"`
	BSCWriters  []BSCWriter `yaml:"bsc_writers"`
}

// Watch is one address and why it is on the list.
type Watch struct {
	Address string `yaml:"address"`
	Label   string `yaml:"label"`
}

// BSCWriter is a stage-writing account and the last nonce accounted for.
type BSCWriter struct {
	Address    string `yaml:"address"`
	Label      string `yaml:"label"`
	KnownNonce uint64 `yaml:"known_nonce"`
}

// Load reads a builtin config by name, or a YAML file by path.
func Load(nameOrPath string) (*Config, error) {
	var raw []byte
	var err error
	if strings.ContainsAny(nameOrPath, "/\\.") {
		raw, err = os.ReadFile(nameOrPath)
	} else {
		raw, err = builtin.ReadFile("builtin/" + nameOrPath + ".yaml")
	}
	if err != nil {
		return nil, fmt.Errorf("deaddrop config %q: %w", nameOrPath, err)
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("deaddrop config %q: %w", nameOrPath, err)
	}
	for _, w := range c.NullReceiver {
		if !isEthAddress(w.Address) {
			return nil, fmt.Errorf("deaddrop config: %q is not an Ethereum address", w.Address)
		}
	}
	for _, w := range c.BSCIndexes {
		if !isEthAddress(w.Address) {
			return nil, fmt.Errorf("deaddrop config: %q is not an Ethereum address", w.Address)
		}
	}
	for _, w := range c.BSCWriters {
		if !isEthAddress(w.Address) {
			return nil, fmt.Errorf("deaddrop config: %q is not a BSC address", w.Address)
		}
	}
	for _, w := range c.TronIndexes {
		if len(w.Address) != 34 || w.Address[0] != 'T' {
			return nil, fmt.Errorf("deaddrop config: %q is not a TRON address", w.Address)
		}
	}
	return &c, nil
}

func isEthAddress(s string) bool {
	if len(s) != 42 || !strings.HasPrefix(strings.ToLower(s), "0x") {
		return false
	}
	for _, r := range s[2:] {
		if !strings.ContainsRune("0123456789abcdefABCDEF", r) {
			return false
		}
	}
	return true
}
