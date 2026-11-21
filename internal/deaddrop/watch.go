package deaddrop

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/n4uu/prowl/internal/source"
)

// Endpoints are the public APIs the watcher reads. All have keyless free
// tiers; overrides exist for tests and for anyone running their own node.
type Endpoints struct {
	Blockscout string // Etherscan-compatible API, default https://eth.blockscout.com/api
	TronGrid   string // default https://api.trongrid.io
	BSCRPC     string // default https://bsc-dataseed.binance.org/
}

func (e Endpoints) withDefaults() Endpoints {
	if e.Blockscout == "" {
		e.Blockscout = "https://eth.blockscout.com/api"
	}
	if e.TronGrid == "" {
		e.TronGrid = "https://api.trongrid.io"
	}
	if e.BSCRPC == "" {
		e.BSCRPC = "https://bsc-dataseed.binance.org/"
	}
	return e
}

// Watcher reads a Config's dead drops.
type Watcher struct {
	C   *source.Client
	E   Endpoints
	Now func() time.Time
}

// Period is a run of consecutive transactions publishing the same C2.
type Period struct {
	C2         string    `json:"c2"`
	IP1        string    `json:"ip1"`
	IP2        string    `json:"ip2"`
	First      time.Time `json:"first"`
	Last       time.Time `json:"last"`
	Txs        int       `json:"txs"`
	FirstBlock uint64    `json:"first_block"`
	LastBlock  uint64    `json:"last_block"`
}

// Transfer is ETH moving into or out of a watched wallet, other than the
// zero-value pointer transactions.
type Transfer struct {
	Time      time.Time `json:"time"`
	Direction string    `json:"direction"` // in or out
	Peer      string    `json:"peer"`
	ValueETH  string    `json:"value_eth"`
	Hash      string    `json:"hash"`
}

// WalletReport is one NullReceiver wallet.
type WalletReport struct {
	Address    string   `json:"address"`
	Label      string   `json:"label"`
	Pointers   int      `json:"pointers"`
	OnSchedule int      `json:"on_schedule"`
	Marker     string   `json:"marker,omitempty"`
	Periods    []Period `json:"periods"`
	Current    *Period  `json:"current,omitempty"`
	// Active is true when the last pointer is under a day old. The bot
	// republishes about every 1000 blocks (3.3 hours), so a quiet day means
	// the wallet has been retired or has run out of gas.
	Active    bool       `json:"active"`
	Transfers []Transfer `json:"transfers"`
	Error     string     `json:"error,omitempty"`
}

// TronReport is one TRON memo index.
type TronReport struct {
	Address     string    `json:"address"`
	Label       string    `json:"label"`
	Outgoing    int       `json:"outgoing"`
	Pointers    int       `json:"pointers"`
	First       time.Time `json:"first,omitempty"`
	Last        time.Time `json:"last,omitempty"`
	LastPointer string    `json:"last_pointer,omitempty"` // BSC tx hash
	Error       string    `json:"error,omitempty"`
}

// WriterReport is one BSC stage writer.
type WriterReport struct {
	Address    string `json:"address"`
	Label      string `json:"label"`
	Nonce      uint64 `json:"nonce"`
	KnownNonce uint64 `json:"known_nonce"`
	// Unaccounted is how many transactions the writer sent after the last
	// one any watched index points to.
	Unaccounted int64 `json:"unaccounted"`
	// Indexed lists nonces above KnownNonce that an Ethereum index points to.
	Indexed []uint64 `json:"indexed,omitempty"`
	Error   string   `json:"error,omitempty"`
}

// Report is the whole watch.
type Report struct {
	Name      string         `json:"name"`
	Generated time.Time      `json:"generated"`
	Wallets   []WalletReport `json:"nullreceiver"`
	Indexes   []IndexReport  `json:"bsc_indexes"`
	Tron      []TronReport   `json:"tron_indexes"`
	Writers   []WriterReport `json:"bsc_writers"`
}

// Run reads every dead drop in the config. Errors are recorded per address
// so one dead API doesn't empty the report.
func (w *Watcher) Run(ctx context.Context, cfg *Config) *Report {
	e := w.E.withDefaults()
	now := time.Now
	if w.Now != nil {
		now = w.Now
	}
	r := &Report{Name: cfg.Name, Generated: now().UTC()}
	for _, x := range cfg.NullReceiver {
		r.Wallets = append(r.Wallets, w.wallet(ctx, e, x, r.Generated))
	}
	for _, x := range cfg.BSCIndexes {
		r.Indexes = append(r.Indexes, w.index(ctx, e, x, r.Generated))
	}
	for _, x := range cfg.TronIndexes {
		r.Tron = append(r.Tron, w.tron(ctx, e, x))
	}
	for _, x := range cfg.BSCWriters {
		wr := w.writer(ctx, e, x)
		// Stages an Ethereum index points to are accounted for.
		for _, ix := range r.Indexes {
			for _, st := range ix.Stages {
				if st.Sender == wr.Address && st.Nonce > x.KnownNonce && st.Nonce < wr.Nonce {
					wr.Unaccounted--
					wr.Indexed = append(wr.Indexed, st.Nonce)
				}
			}
		}
		r.Writers = append(r.Writers, wr)
	}
	return r
}

type ethTx struct {
	Hash      string `json:"hash"`
	Block     string `json:"blockNumber"`
	TimeStamp string `json:"timeStamp"`
	From      string `json:"from"`
	To        string `json:"to"`
	Value     string `json:"value"`
	IsError   string `json:"isError"`
}

func (w *Watcher) ethTxs(ctx context.Context, e Endpoints, addr string) ([]ethTx, error) {
	var all []ethTx
	for page := 1; page <= 20; page++ {
		q := url.Values{
			"module": {"account"}, "action": {"txlist"}, "address": {addr},
			"startblock": {"0"}, "endblock": {"99999999"},
			"page": {strconv.Itoa(page)}, "offset": {"1000"}, "sort": {"asc"},
		}
		body, _, err := w.C.Do(ctx, source.Request{Method: http.MethodGet, URL: e.Blockscout + "?" + q.Encode()})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Message string          `json:"message"`
			Result  json.RawMessage `json:"result"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			return nil, fmt.Errorf("blockscout: %w", err)
		}
		var txs []ethTx
		if len(resp.Result) > 0 && resp.Result[0] == '[' {
			if err := json.Unmarshal(resp.Result, &txs); err != nil {
				return nil, fmt.Errorf("blockscout: %w", err)
			}
		}
		all = append(all, txs...)
		if len(txs) < 1000 {
			break
		}
	}
	return all, nil
}

func unix(s string) time.Time {
	n, _ := strconv.ParseInt(s, 10, 64)
	return time.Unix(n, 0).UTC()
}

func weiToETH(s string) string {
	v, ok := new(big.Int).SetString(s, 10)
	if !ok || v.Sign() < 0 {
		return s
	}
	q, r := new(big.Int).QuoRem(v, big.NewInt(1e18), new(big.Int))
	frac := strings.TrimRight(fmt.Sprintf("%018s", r.String()), "0")
	if frac == "" {
		return q.String()
	}
	return q.String() + "." + frac
}

func (w *Watcher) wallet(ctx context.Context, e Endpoints, x Watch, now time.Time) WalletReport {
	rep := WalletReport{Address: strings.ToLower(x.Address), Label: x.Label, Periods: []Period{}, Transfers: []Transfer{}}
	txs, err := w.ethTxs(ctx, e, rep.Address)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	sort.SliceStable(txs, func(i, j int) bool {
		bi, _ := strconv.ParseUint(txs[i].Block, 10, 64)
		bj, _ := strconv.ParseUint(txs[j].Block, 10, 64)
		return bi < bj
	})
	for _, t := range txs {
		from, to := strings.ToLower(t.From), strings.ToLower(t.To)
		ts := unix(t.TimeStamp)
		block, _ := strconv.ParseUint(t.Block, 10, 64)
		if from == rep.Address && t.Value == "0" && t.IsError != "1" {
			p, err := DecodeRecipient(to)
			if err == nil && p.Valid() {
				rep.Pointers++
				rep.Marker = p.Marker
				if OnSchedule(block) {
					rep.OnSchedule++
				}
				c2 := p.String()
				n := len(rep.Periods)
				if n > 0 && rep.Periods[n-1].C2 == c2 {
					rep.Periods[n-1].Last, rep.Periods[n-1].LastBlock = ts, block
					rep.Periods[n-1].Txs++
				} else {
					rep.Periods = append(rep.Periods, Period{C2: c2, IP1: p.IP1.String(), IP2: p.IP2.String(),
						First: ts, Last: ts, Txs: 1, FirstBlock: block, LastBlock: block})
				}
				continue
			}
		}
		if t.Value != "0" && t.Value != "" {
			tr := Transfer{Time: ts, ValueETH: weiToETH(t.Value), Hash: t.Hash}
			if from == rep.Address {
				tr.Direction, tr.Peer = "out", to
			} else {
				tr.Direction, tr.Peer = "in", from
			}
			rep.Transfers = append(rep.Transfers, tr)
		}
	}
	if n := len(rep.Periods); n > 0 {
		cur := rep.Periods[n-1]
		rep.Current = &cur
		rep.Active = now.Sub(cur.Last) < 24*time.Hour
	}
	return rep
}

type tronTx struct {
	TxID      string `json:"txID"`
	Timestamp int64  `json:"block_timestamp"`
	RawData   struct {
		Data string `json:"data"`
	} `json:"raw_data"`
}

func (w *Watcher) tron(ctx context.Context, e Endpoints, x Watch) TronReport {
	rep := TronReport{Address: x.Address, Label: x.Label}
	next := e.TronGrid + "/v1/accounts/" + x.Address + "/transactions?limit=200&only_from=true&order_by=block_timestamp,asc"
	for i := 0; next != "" && i < 50; i++ {
		body, _, err := w.C.Do(ctx, source.Request{Method: http.MethodGet, URL: next})
		if err != nil {
			rep.Error = err.Error()
			return rep
		}
		var resp struct {
			Data []tronTx `json:"data"`
			Meta struct {
				Links struct {
					Next string `json:"next"`
				} `json:"links"`
			} `json:"meta"`
		}
		if err := json.Unmarshal(body, &resp); err != nil {
			rep.Error = "trongrid: " + err.Error()
			return rep
		}
		for _, t := range resp.Data {
			ts := time.UnixMilli(t.Timestamp).UTC()
			if rep.Outgoing == 0 {
				rep.First = ts
			}
			rep.Outgoing++
			rep.Last = ts
			if h := DecodeMemo(t.RawData.Data); h != "" {
				rep.Pointers++
				rep.LastPointer = h
			}
		}
		next = resp.Meta.Links.Next
		if e.TronGrid != "https://api.trongrid.io" && next != "" {
			// keep test servers self-contained: rewrite the host of "next"
			if u, err := url.Parse(next); err == nil {
				next = e.TronGrid + u.RequestURI()
			}
		}
	}
	return rep
}

func (w *Watcher) writer(ctx context.Context, e Endpoints, x BSCWriter) WriterReport {
	rep := WriterReport{Address: strings.ToLower(x.Address), Label: x.Label, KnownNonce: x.KnownNonce}
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "eth_getTransactionCount", "params": []string{rep.Address, "latest"}})
	raw, _, err := w.C.Do(ctx, source.Request{Method: http.MethodPost, URL: e.BSCRPC, Body: body,
		Header: http.Header{"Content-Type": {"application/json"}}})
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	var resp struct {
		Result string `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil || resp.Error != nil {
		if resp.Error != nil {
			rep.Error = "bsc rpc: " + resp.Error.Message
		} else {
			rep.Error = "bsc rpc: " + err.Error()
		}
		return rep
	}
	n, err := strconv.ParseUint(strings.TrimPrefix(resp.Result, "0x"), 16, 64)
	if err != nil {
		rep.Error = "bsc rpc: bad nonce " + resp.Result
		return rep
	}
	// eth_getTransactionCount is the next nonce, so the last sent one is n-1.
	rep.Nonce = n
	rep.Unaccounted = int64(n) - int64(x.KnownNonce) - 1
	return rep
}

// Stage is one BSC transaction an index wallet pointed to.
type Stage struct {
	BSCBlock uint64    `json:"bsc_block"`
	TxIndex  int       `json:"tx_index"`
	BSCTx    string    `json:"bsc_tx,omitempty"`
	Sender   string    `json:"sender,omitempty"`
	Nonce    uint64    `json:"nonce"`
	First    time.Time `json:"first"`
	Last     time.Time `json:"last"`
	Pointers int       `json:"pointers"`
}

// IndexReport is one BSC-index wallet.
type IndexReport struct {
	Address    string  `json:"address"`
	Label      string  `json:"label"`
	Pointers   int     `json:"pointers"`
	OnSchedule int     `json:"on_schedule"`
	Stages     []Stage `json:"stages"`
	Active     bool    `json:"active"`
	Error      string  `json:"error,omitempty"`
}

func (w *Watcher) bscRPC(ctx context.Context, e Endpoints, method string, params ...any) (json.RawMessage, error) {
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
	raw, _, err := w.C.Do(ctx, source.Request{Method: http.MethodPost, URL: e.BSCRPC, Body: body,
		Header: http.Header{"Content-Type": {"application/json"}}})
	if err != nil {
		return nil, err
	}
	var resp struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("bsc rpc: %w", err)
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("bsc rpc: %s", resp.Error.Message)
	}
	return resp.Result, nil
}

func hexUint(s string) uint64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	return n
}

func (w *Watcher) index(ctx context.Context, e Endpoints, x Watch, now time.Time) IndexReport {
	rep := IndexReport{Address: strings.ToLower(x.Address), Label: x.Label, Stages: []Stage{}}
	txs, err := w.ethTxs(ctx, e, rep.Address)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	pos := map[[2]uint64]int{}
	for _, t := range txs {
		// Unlike NullReceiver these pointers carry a token amount (100 wei),
		// so any outgoing, successful transaction counts.
		if strings.ToLower(t.From) != rep.Address || t.IsError == "1" {
			continue
		}
		sp, err := DecodeStagePointer(t.To)
		if err != nil {
			continue
		}
		block, _ := strconv.ParseUint(t.Block, 10, 64)
		ts := unix(t.TimeStamp)
		rep.Pointers++
		if OnSchedule256(block) {
			rep.OnSchedule++
		}
		k := [2]uint64{sp.Block, uint64(sp.Index)}
		i, ok := pos[k]
		if !ok {
			i = len(rep.Stages)
			pos[k] = i
			rep.Stages = append(rep.Stages, Stage{BSCBlock: sp.Block, TxIndex: sp.Index, First: ts})
		}
		rep.Stages[i].Last = ts
		rep.Stages[i].Pointers++
	}
	for i := range rep.Stages {
		st := &rep.Stages[i]
		raw, err := w.bscRPC(ctx, e, "eth_getBlockByNumber", fmt.Sprintf("0x%x", st.BSCBlock), false)
		if err != nil {
			rep.Error = err.Error()
			continue
		}
		var blk struct {
			Transactions []string `json:"transactions"`
		}
		if json.Unmarshal(raw, &blk) != nil || st.TxIndex >= len(blk.Transactions) {
			continue
		}
		st.BSCTx = blk.Transactions[st.TxIndex]
		raw, err = w.bscRPC(ctx, e, "eth_getTransactionByHash", st.BSCTx)
		if err != nil {
			rep.Error = err.Error()
			continue
		}
		var tx struct {
			From  string `json:"from"`
			Nonce string `json:"nonce"`
		}
		if json.Unmarshal(raw, &tx) == nil {
			st.Sender, st.Nonce = strings.ToLower(tx.From), hexUint(tx.Nonce)
		}
	}
	if n := len(rep.Stages); n > 0 {
		last := rep.Stages[0].Last
		for _, s := range rep.Stages {
			if s.Last.After(last) {
				last = s.Last
			}
		}
		rep.Active = now.Sub(last) < 24*time.Hour
	}
	return rep
}
