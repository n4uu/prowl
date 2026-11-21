package deaddrop

import (
	"encoding/hex"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Pointer is what a NullReceiver recipient address decodes to.
type Pointer struct {
	IP1, IP2 netip.Addr
	// Marker is the padding after the two addresses when it is printable
	// ASCII ("helloipbot!!" in every PolinRider transaction so far). Empty
	// when the tail is binary, which is what a plain transfer to a real
	// address looks like.
	Marker string
}

// Valid reports whether the address carries the operator's padding rather
// than being an ordinary transfer that happens to decode to two IPs.
func (p Pointer) Valid() bool { return p.Marker != "" }

func (p Pointer) String() string {
	if p.IP1 == p.IP2 {
		return p.IP1.String()
	}
	return p.IP1.String() + " " + p.IP2.String()
}

// DecodeRecipient reads two IPv4 addresses out of the first eight bytes of
// an Ethereum address, the way the loader's decodeAddress() does.
func DecodeRecipient(to string) (Pointer, error) {
	s := strings.TrimPrefix(strings.ToLower(to), "0x")
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 20 {
		return Pointer{}, fmt.Errorf("not an address: %q", to)
	}
	p := Pointer{
		IP1: netip.AddrFrom4([4]byte(b[0:4])),
		IP2: netip.AddrFrom4([4]byte(b[4:8])),
	}
	tail := b[8:]
	printable := true
	for _, c := range tail {
		if c < 0x20 || c > 0x7e {
			printable = false
			break
		}
	}
	if printable {
		p.Marker = string(tail)
	}
	return p, nil
}

var bscHash = regexp.MustCompile(`^0x[0-9a-f]{64}$`)

// DecodeMemo turns a TRON memo (hex, as TronGrid returns raw_data.data)
// into the BSC transaction hash it points to: hex-decode, reverse. Returns
// "" when the memo is something else.
func DecodeMemo(memoHex string) string {
	b, err := hex.DecodeString(memoHex)
	if err != nil {
		return ""
	}
	r := []rune(string(b))
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	s := string(r)
	if !bscHash.MatchString(s) {
		return ""
	}
	return s
}

// OnSchedule reports whether a block number is one the loader checks: the
// loader rounds the chain head down to a multiple of 1000 and looks at that
// block and its neighbours, so the operator's bot publishes there.
func OnSchedule(block uint64) bool {
	m := block % 1000
	return m == 0 || m == 1 || m == 999
}
