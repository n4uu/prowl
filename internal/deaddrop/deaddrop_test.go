package deaddrop

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/n4uu/prowl/internal/source"
)

// recipient builds a NullReceiver-style address: two IPv4s, then padding.
func recipient(ip1, ip2 [4]byte, pad string) string {
	b := append(append(ip1[:], ip2[:]...), []byte(pad)...)
	return "0x" + hex.EncodeToString(b)
}

func TestDecodeRecipient(t *testing.T) {
	// Same shape as the live transactions: one IP twice, "helloipbot!!".
	p, err := DecodeRecipient("0x5f87b5545f87b55468656c6c6f6970626f742121")
	if err != nil {
		t.Fatal(err)
	}
	if p.String() != "95.135.181.84" || p.Marker != "helloipbot!!" || !p.Valid() {
		t.Fatalf("got %+v", p)
	}
	// An ordinary transfer to a real address decodes to two IPs too, but
	// the binary tail gives it away.
	p, _ = DecodeRecipient("0xf97062cb1b6ffa18b88e9faea373ed288a87ecd0")
	if p.Valid() {
		t.Fatalf("plain address taken as a pointer: %+v", p)
	}
	if _, err := DecodeRecipient("0x1234"); err == nil {
		t.Fatal("short address accepted")
	}
}

func TestDecodeMemo(t *testing.T) {
	h := "0x804b000af7d7e4337ba5db28bb367da64a08391de09ffb07847ac897c5f82954"
	rev := []byte(h)
	for i, j := 0, len(rev)-1; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	if got := DecodeMemo(hex.EncodeToString(rev)); got != h {
		t.Fatalf("got %q", got)
	}
	if got := DecodeMemo(hex.EncodeToString([]byte("Mxy custom memo text"))); got != "" {
		t.Fatalf("test memo decoded to %q", got)
	}
}

func TestOnSchedule(t *testing.T) {
	for b, want := range map[uint64]bool{26464000: true, 26463999: true, 26464001: true, 26464002: false, 26187571: false} {
		if OnSchedule(b) != want {
			t.Errorf("OnSchedule(%d) = %v", b, !want)
		}
	}
}

type fakeChains struct {
	eth  map[string][]ethTx
	tron map[string][]tronTx
	page int // TronGrid page size, to exercise pagination
	nonc string
}

func (f *fakeChains) handler(t *testing.T) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/eth/api", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("module") != "account" || q.Get("action") != "txlist" {
			t.Errorf("unexpected blockscout query %s", r.URL.RawQuery)
		}
		res := f.eth[strings.ToLower(q.Get("address"))]
		if q.Get("page") != "1" {
			res = nil
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "1", "message": "OK", "result": res})
	})
	mux.HandleFunc("/tron/v1/accounts/", func(w http.ResponseWriter, r *http.Request) {
		addr := strings.Split(strings.TrimPrefix(r.URL.Path, "/tron/v1/accounts/"), "/")[0]
		all := f.tron[addr]
		start := 0
		if fp := r.URL.Query().Get("fingerprint"); fp != "" {
			fmt.Sscanf(fp, "%d", &start)
		}
		end := min(start+f.page, len(all))
		resp := map[string]any{"data": all[start:end], "success": true, "meta": map[string]any{}}
		if end < len(all) {
			resp["meta"] = map[string]any{"links": map[string]any{"next": fmt.Sprintf("https://api.trongrid.io/v1/accounts/%s/transactions?fingerprint=%d", addr, end)}}
		}
		json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/bsc", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if !bytes.Contains(b, []byte("eth_getTransactionCount")) {
			t.Errorf("unexpected rpc %s", b)
		}
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":%q}`, f.nonc)
	})
	return mux
}

func memo(h string) string {
	r := []byte(h)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return hex.EncodeToString(r)
}

func TestWatcher(t *testing.T) {
	const wallet = "0x00000000000000000000000000000000000c0ffe"
	a := recipient([4]byte{192, 0, 2, 10}, [4]byte{192, 0, 2, 10}, "helloipbot!!")
	b := recipient([4]byte{198, 51, 100, 7}, [4]byte{198, 51, 100, 7}, "helloipbot!!")
	tx := func(block uint64, ts int64, from, to, value string) ethTx {
		return ethTx{Hash: fmt.Sprintf("0x%064x", block), Block: fmt.Sprint(block), TimeStamp: fmt.Sprint(ts), From: from, To: to, Value: value, IsError: "0"}
	}
	f := &fakeChains{
		eth: map[string][]ethTx{wallet: {
			tx(1000, 1788500000, "0x00000000000000000000000000000000000f0d5e", wallet, "20670600000000000"),
			tx(2000, 1788510000, wallet, a, "0"),
			tx(2999, 1788520000, wallet, a, "0"),
			tx(3517, 1788530000, wallet, b, "0"), // off schedule
			tx(4000, 1788540000, wallet, b, "0"),
			tx(4100, 1788541000, wallet, "0xf97062cb1b6ffa18b88e9faea373ed288a87ecd0", "29295496889655864"),
		}},
		tron: map[string][]tronTx{},
		page: 2,
		nonc: "0x15f",
	}
	idx := "TQqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq"
	for i := 0; i < 5; i++ {
		var x tronTx
		x.TxID = fmt.Sprint(i)
		x.Timestamp = time.Date(2026, 10, 1+i, 0, 0, 0, 0, time.UTC).UnixMilli()
		if i == 0 {
			x.RawData.Data = hex.EncodeToString([]byte("Mxy custom memo text"))
		} else {
			x.RawData.Data = memo(fmt.Sprintf("0x%064x", i))
		}
		f.tron[idx] = append(f.tron[idx], x)
	}
	srv := httptest.NewServer(f.handler(t))
	defer srv.Close()

	cfg := &Config{
		Name:         "test",
		NullReceiver: []Watch{{Address: wallet, Label: "w"}},
		TronIndexes:  []Watch{{Address: idx, Label: "i"}},
		BSCWriters:   []BSCWriter{{Address: "0x9bc1355344b54dedf3e44296916ed15653844509", Label: "b", KnownNonce: 297}},
	}
	w := &Watcher{C: source.NewClient(nil, false), Now: func() time.Time { return time.Unix(1788541000, 0).Add(2 * time.Hour) }, E: Endpoints{Blockscout: srv.URL + "/eth/api", TronGrid: srv.URL + "/tron", BSCRPC: srv.URL + "/bsc"}}
	r := w.Run(context.Background(), cfg)

	wr := r.Wallets[0]
	if wr.Error != "" {
		t.Fatal(wr.Error)
	}
	if wr.Pointers != 4 || wr.OnSchedule != 3 || wr.Marker != "helloipbot!!" {
		t.Fatalf("wallet = %+v", wr)
	}
	if len(wr.Periods) != 2 || wr.Periods[0].C2 != "192.0.2.10" || wr.Periods[0].Txs != 2 || wr.Periods[1].C2 != "198.51.100.7" {
		t.Fatalf("periods = %+v", wr.Periods)
	}
	if wr.Current == nil || wr.Current.C2 != "198.51.100.7" || wr.Current.LastBlock != 4000 {
		t.Fatalf("current = %+v", wr.Current)
	}
	if !wr.Active {
		t.Fatal("wallet should be active two hours after its last pointer")
	}
	if len(wr.Transfers) != 2 || wr.Transfers[0].Direction != "in" || wr.Transfers[0].ValueETH != "0.0206706" || wr.Transfers[1].ValueETH != "0.029295496889655864" {
		t.Fatalf("transfers = %+v", wr.Transfers)
	}

	tr := r.Tron[0]
	if tr.Error != "" || tr.Outgoing != 5 || tr.Pointers != 4 || tr.LastPointer != fmt.Sprintf("0x%064x", 4) {
		t.Fatalf("tron = %+v", tr)
	}
	if !tr.Last.Equal(time.Date(2026, 10, 5, 0, 0, 0, 0, time.UTC)) {
		t.Fatalf("tron last = %v", tr.Last)
	}

	br := r.Writers[0]
	if br.Error != "" || br.Nonce != 351 || br.Unaccounted != 53 {
		t.Fatalf("writer = %+v", br)
	}

	var text, csvOut bytes.Buffer
	WriteText(&text, r)
	if !strings.Contains(text.String(), "198.51.100[.]7  <- current") || !strings.Contains(text.String(), "53 transactions after the last indexed one") {
		t.Fatalf("text:\n%s", text.String())
	}
	if err := WriteCSV(&csvOut, r); err != nil {
		t.Fatal(err)
	}
	if lines := strings.Count(csvOut.String(), "\n"); lines != 3 {
		t.Fatalf("csv has %d lines:\n%s", lines, csvOut.String())
	}
}

func TestWeiToETH(t *testing.T) {
	for in, want := range map[string]string{"0": "0", "1": "0.000000000000000001", "1000000000000000000": "1", "29295496889655864": "0.029295496889655864", "60000000000000000": "0.06"} {
		if got := weiToETH(in); got != want {
			t.Errorf("weiToETH(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestBuiltinConfig(t *testing.T) {
	c, err := Load("polinrider")
	if err != nil {
		t.Fatal(err)
	}
	for _, x := range c.TronIndexes {
		if x.Label == "" || strings.Contains(x.Label, "}") {
			t.Errorf("label for %s parsed as %q", x.Address, x.Label)
		}
	}
	if len(c.NullReceiver) != 2 || len(c.TronIndexes) != 7 || len(c.BSCWriters) != 1 || c.BSCWriters[0].KnownNonce != 297 {
		t.Fatalf("config = %+v", c)
	}
	if _, err := Load("nope"); err == nil {
		t.Fatal("missing builtin accepted")
	}
}
