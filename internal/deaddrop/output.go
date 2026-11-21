package deaddrop

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// defang turns 95.135.181.84 into 95.135.181[.]84 for anything a human
// might paste into a browser.
func defang(ip string) string {
	i := strings.LastIndexByte(ip, '.')
	if i < 0 {
		return ip
	}
	return ip[:i] + "[.]" + ip[i+1:]
}

// WriteText prints a summary for a terminal.
func WriteText(out io.Writer, r *Report) {
	fmt.Fprintf(out, "%s dead drops, %s\n", r.Name, r.Generated.Format(time.RFC3339))
	for _, w := range r.Wallets {
		fmt.Fprintf(out, "\nNullReceiver %s  (%s)\n", w.Address, w.Label)
		if w.Error != "" {
			fmt.Fprintf(out, "  error: %s\n", w.Error)
			continue
		}
		fmt.Fprintf(out, "  %d pointer transactions, %d on the 1000-block schedule, padding %q\n", w.Pointers, w.OnSchedule, w.Marker)
		for _, p := range w.Periods {
			cur := ""
			if w.Current != nil && p.FirstBlock == w.Current.FirstBlock {
				cur = "  <- current"
				if !w.Active {
					cur = "  <- last (wallet quiet since " + p.Last.Format("2006-01-02") + ")"
				}
			}
			fmt.Fprintf(out, "  %s .. %s  %4d txs  %s%s\n", p.First.Format("2006-01-02 15:04"), p.Last.Format("2006-01-02 15:04"), p.Txs, defangC2(p), cur)
		}
		for _, t := range w.Transfers {
			fmt.Fprintf(out, "  %s  %-3s %s ETH  %s\n", t.Time.Format("2006-01-02 15:04"), t.Direction, t.ValueETH, t.Peer)
		}
	}
	for _, x := range r.Indexes {
		fmt.Fprintf(out, "\nBSC index %s  (%s)\n", x.Address, x.Label)
		if x.Error != "" {
			fmt.Fprintf(out, "  error: %s\n", x.Error)
		}
		fmt.Fprintf(out, "  %d pointer transactions, %d on the 256-block schedule, active %v\n", x.Pointers, x.OnSchedule, x.Active)
		for _, st := range x.Stages {
			fmt.Fprintf(out, "  %s .. %s  %4d txs  BSC block %d #%d  %s  nonce %d\n", st.First.Format("2006-01-02 15:04"), st.Last.Format("2006-01-02 15:04"), st.Pointers, st.BSCBlock, st.TxIndex, st.BSCTx, st.Nonce)
		}
	}
	if len(r.Tron) > 0 {
		fmt.Fprintf(out, "\nTRON indexes\n")
	}
	for _, t := range r.Tron {
		if t.Error != "" {
			fmt.Fprintf(out, "  %s  error: %s\n", t.Address, t.Error)
			continue
		}
		last := "-"
		if !t.Last.IsZero() {
			last = t.Last.Format("2006-01-02 15:04")
		}
		fmt.Fprintf(out, "  %s  %3d pointers / %3d txs, last %s  (%s)\n", t.Address, t.Pointers, t.Outgoing, last, t.Label)
	}
	for _, b := range r.Writers {
		if b.Error != "" {
			fmt.Fprintf(out, "\nBSC writer %s  error: %s\n", b.Address, b.Error)
			continue
		}
		fmt.Fprintf(out, "\nBSC writer %s: next nonce %d, %d transactions after nonce %d that no watched index points to", b.Address, b.Nonce, b.Unaccounted, b.KnownNonce)
		if len(b.Indexed) > 0 {
			fmt.Fprintf(out, " (indexed from Ethereum: %v)", b.Indexed)
		}
		fmt.Fprintln(out)
	}
}

func defangC2(p Period) string {
	if p.IP1 == p.IP2 {
		return defang(p.IP1)
	}
	return defang(p.IP1) + " " + defang(p.IP2)
}

// WriteCSV writes one row per C2 period, the feed a blocklist wants.
func WriteCSV(out io.Writer, r *Report) error {
	cw := csv.NewWriter(out)
	_ = cw.Write([]string{"wallet", "ip1", "ip2", "first_seen", "last_seen", "pointer_txs", "first_block", "last_block", "current"})
	for _, w := range r.Wallets {
		for _, p := range w.Periods {
			cur := w.Active && w.Current != nil && p.FirstBlock == w.Current.FirstBlock
			_ = cw.Write([]string{w.Address, p.IP1, p.IP2, p.First.Format(time.RFC3339), p.Last.Format(time.RFC3339),
				strconv.Itoa(p.Txs), strconv.FormatUint(p.FirstBlock, 10), strconv.FormatUint(p.LastBlock, 10), strconv.FormatBool(cur)})
		}
	}
	cw.Flush()
	return cw.Error()
}
