package rawsock

/******************************************************************************
Rawsock

This package has functions to set up use, and abuse raw sockets, initially and
mostly for jacking up TCP flags to perpetrate old hits such as TCP 1/2-open
scanning, XMAS-tree scans, ACK scans, and the like.
Developed for use with Netbang, but should be useful in other fun contexts.

AUTHOR: CT Geigner "chux0r"
DATE:   29FEB2024
ORG:	Megaohm.net
License: GPL v3
******************************************************************************/

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	// TCP FLAGS
	CWR = 128 // 10000000 Congestion Window Reduced
	ECE = 64  // 01000000 ECN Echo
	URG = 32  // 00100000
	ACK = 16  // 00010000
	PSH = 8   // 00001000
	RST = 4   // 00000100
	SYN = 2   // 00000010
	FIN = 1   // 00000001
)

// TCP HEADER, ILLUSTRATED - *Dramatic musical number ensues...*
type TCPHeadr struct {
	/*                                TCP Header
	 byte +-----[ 0 ]-----+-----[ 1 ]-----+-----[ 2 ]-----+-----[ 3 ]-----+
		  |0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|0 1 2 3 4 5 6 7|
		  +-------+-------+-------+-------+-------+-------+-------+-------+ <--+
	   0  |        SRC PORT[srcP]         |         DST PORT[dstP]        |    |
		  +-------+-------+-------+-------+-------+-------+-------+-------+    |
	   4  |               .        SEQ NUMBER[seqN]       .               |    |
		  +-------+-------+-------+-------+-------+-------+-------+-------+    |
	   8  |               .        (when ACK set)         .               |    |
	o     |               .  ACKNOWLEDGEMENT NUMBER[ackN] .               |    |
	f     +-------+-------+-+-+-+-+-+-+-+-+-------+-------+-------+-------+    |
	f     |  DATA | RESVD |[___ FLAGS ___]|               .               |    h
	s  12 |  OFF  | [0000]|C|E|U|A|P|R|S|F|            RECEIVE            |    e
	e     |  SET† |       |W|C|R|C|S|S|Y|I|      WINDOW SIZE[winSz]       |    a
	t     |    [offRet]   |R|E|G|K|H|T|N|N|               .               |    d
		  +-------+-------+-+-+-+-+-+-+-+-+-------+-------+-------+-------+    e
	   16 |         CHECKSUM[cksum]       |        (when URG set)         |    r
		  |               .               |        URG PTR[urgptr]        |    |
		  +-------+-------+-+-+-+-+-+-+-+-+-------+-------+-------+-------+    |
	   20 |               .               .               .               |    |
	  -56 |         OPTIONS[opts] (LEN DETERMINED BY [DATA OFFSET])       |    |
		  |               .               .               .               |    |
		  +-------+-------+-------+-------+-------+-------+-------+-------+ <--+
		  |               .               .               .               |    |
		  |               .          D  A  T  A           .               |    d
		  |               .               .               .               |    a
		  |               .               .               .               |    t
		  |               .               .               .               |    a
		  :               .               .               .               :    :
		  ↓               ↓               ↓               ↓               ↓    ↓

		  †Data Offset is value * 4 byte chunks == total size of tcp header
		  w/o options min size is 20B; max is 60B. So, valid Data Offset is
		  5-15. [0x0101-0x1111]

		  ACK options, we'll not be using these since we'll be initiating.
		  PAD header to 32-bit boundary when using.
		  Might have opportunity to hide limited data in here?
	*/
	srcP uint16 // bind to port 0 and OS will do the work for us in finding a suitable ephemeral port to use
	dstP uint16 // Set at run-time
	seqN uint32 // If we're lazy, we can be fingerprinted with this. So, rand() it up, lazy ass...
	// ALSO: if you're going to really use it (who knows?), next SEQ number is seqN (last) + DataPacketLen (next)
	ackN uint32 // AFAIK Netbang will be doing "initiate" actions: So this will be 0x0 unless that changes.
	// BUT ackN would be DST's last seqN+1
	offRet uint8  // data offset + "0000"/"reserved". Not going to mess with it here. Values 5-15 look like 0x01010000 - 0x11110000
	flags  uint8  // all of the above, just to get to this :) Jack with all of em in packet constructor: (*TCPHeadr) Misconfigure()
	winSz  uint16 // Flow control stuff: "the size of the window we're willing to receive".
	cksum  uint16 // srcIP, dstIP, {0x06(TCP) or UDP 0x11}, {byteLen of header+data} )) ones-complement of sum of these items
	// The OS network stack will calc/set this for us if set to 0 (I think...)!
	urgptr uint16 // n/a. right until we wanna mess wid it
	//<----------------- MARK: 20 bytes (TCP header min len)

	//--------- optional bytes 21 to 56 below --------------
	opts []byte
	data []byte
}

// Initialize a TCP header instance with some values that are reasonable (ONLY in the context of netscanning I guess...)
func (th *TCPHeadr) Init() {
	th = &TCPHeadr{
		srcP: 0,                                                          // ok; Zero is fine. OS sets ephemeral port
		dstP: 0,                                                          // set (with MisconfigureTCP()) before use; value 0 is test/error condition
		seqN: (rand.New(rand.NewSource(time.Now().UnixNano()))).Uint32(), // GOOD ENUF!
		// SEQN Note: RNG might stutter and give same RNs when used with concurrence. As long as it doesn't across executions, we don't mind terribly.
		// It matters in "real" netwk apps, but I think likely not with the parlor tricks we're perpetrating LOL.
		ackN:   0x0,                           // keep; ok
		offRet: 0x50,                          // 0101, or five 4-byte-parts (20 bytes) distance to packet end (minimum)
		flags:  0x00,                          // set before use; 00000000, "no flags set" is error condition.
		winSz:  0xffff,                        //
		cksum:  0x0,                           // keep fn <-- NO CHECKSUM. MANUAL SET, SYSCALL, OR OS AUTOMAGIC?
		urgptr: 0x0,                           // can mess with, depending on application. ok to keep;
		opts:   []byte{0x0},                   // "End of Option List Option". Can mess with- adjust offRet when you do. ok to keep;
		data:   []byte{0x4c, 0x4f, 0x4c, 0x0}, //LOL[EOF]
	}
}

// Configure TCP header, full mayhem options afoot. Does everything from "normal" to "WTF". FAFO
func (th *TCPHeadr) MisconfigureTCP(port uint16, flg uint8, wsz uint16, opt []byte) {
	th.dstP = port
	th.flags = flg
	th.winSz = wsz
	th.opts = opt
}

// Marshal the payload: Network-byte-order everything, pls
func (th *TCPHeadr) Marshal() []byte {
	bufr := new(bytes.Buffer)
	binary.Write(bufr, binary.BigEndian, th.srcP)
	binary.Write(bufr, binary.BigEndian, th.dstP)
	binary.Write(bufr, binary.BigEndian, th.seqN)
	binary.Write(bufr, binary.BigEndian, th.ackN)
	binary.Write(bufr, binary.BigEndian, th.offRet)
	binary.Write(bufr, binary.BigEndian, th.flags)
	binary.Write(bufr, binary.BigEndian, th.winSz)
	binary.Write(bufr, binary.BigEndian, th.cksum)
	binary.Write(bufr, binary.BigEndian, th.urgptr)
	binary.Write(bufr, binary.BigEndian, th.opts)
	binary.Write(bufr, binary.BigEndian, th.data)

	return bufr.Bytes()
}

// Things on the 'net. Targets, bystanders, our stuff, everything. This is how we can describe them
// Made to replace "NetThang".
type NetThang struct {
	Addr   string           // Unevaluated names or IPs
	Hostn  string           // Hostname in "wah.blah.com" format. Can be just a domain name if DNS CNAME record is defined.
	Domain string           // Domains in "blah.com" format
	IP     net.IP           // []byte Using std library defs, no sense reinventing any of this
	Mask   net.IPMask       // []byte
	Port   uint16           // TCP or UDP portnumber
	Mac    net.HardwareAddr // layer 2; local net
}

// (*NetThang).Network() and (*NetThang).String() implement the net.Addr interface, used in PacketConn.WriteTo()
func (ts *NetThang) Network() string {
	return "ip4:tcp"
}

// (*NetThang).Network() and (*NetThang).String() implement the net.Addr interface, used in PacketConn.WriteTo()
func (ts *NetThang) String() string {
	return fmt.Sprint(ts.IP.String(), ":", strconv.Itoa(int(ts.Port)))
}

// Top-level domain, no dots, eg: "com", "edu", "org", etc.
func (ts *NetThang) TLD() string {
	if ts.Hostn == "" {
		return ""
	}
	t := strings.Split(ts.Hostn, ".")
	return t[len(t)-1]
}
