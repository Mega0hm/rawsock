package rawsock

import (
	"fmt"
	"testing"
)

func TestMisconfigureTCP(t *testing.T) {
	var tH = &TCPHeadr{}
	tH.Init() // twofer - we're testing Init() as well here

	// Thought; hold onto for later: Can I fingerprint, or do others fingerprint based on MSS value (Win seems to do MSS 1460, others do 1500)?
	var opts = []byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02}
	tH.MisconfigureTCP(80, SYN, 0x0000faf0, opts) // tcp port 80 / SYN scan / oooOh xFAFO LOL (0xfaf0 window size) / MSS value: 1460, window scaling bitshift: 8, SACK permitted
	fmt.Print("\nTesting: (*TCPHeadr).Misconfigure()\nArgs: 80, SYN, 0x0000faf0, []byte{0x02, 0x04, 0x05, 0xb4, 0x01, 0x03, 0x03, 0x08, 0x01, 0x01, 0x04, 0x02}")
	if tH.dstP != 80 {
		t.Fatalf("\n\t\n(*TCPHeadr).Misconfigure() :FAIL: DST Port = %q, want: %v\n========================================", tH.dstP, 80)
	} else if tH.flags != SYN {
		t.Fatalf("\n\t(*TCPHeadr).Misconfigure() :FAIL: Flags set = %q, want: %v\n========================================", tH.flags, SYN)
	} else if tH.winSz != 0x0000faf0 {
		t.Fatalf("\n\t(*TCPHeadr).Misconfigure() :FAIL: Window size set = %q, want: %v\n========================================", tH.winSz, 0x0000faf0)
	}
	for i := 0; i < len(tH.opts); i++ {
		if tH.opts[i] != opts[i] {
			t.Fatalf("\n\t(*TCPHeadr).Misconfigure() :FAIL: Options set = %X, want: %X. (Options set, ALL: %v\n========================================", tH.opts[i], opts[i], tH.opts)
		}
	}
	fmt.Print("\n\n(*TCPHeadr).Misconfigure(): PASS!\n========================================")
}

func TestMarshal(t *testing.T) {
	// 0 1 2 3 4 5 6 7 8 9 A B C D E F... : 23 bytes
	var refblob = []byte{0x0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x8, 0x9, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17}
	// Test header. PASS == match refblob once marshalled
	var tH = TCPHeadr{
		srcP:   0x0001,
		dstP:   0x0203,
		seqN:   0x04050607,
		ackN:   0x08090a0b,
		offRet: 0x0c,
		flags:  0x0d,
		winSz:  0x0e0f,
		cksum:  0x1011,
		urgptr: 0x1213,
		opts:   []byte{0x14, 0x15},
		data:   []byte{0x16, 0x17},
	}
	fmt.Print("\n\nTesting: (*TCPHeadr).Marshal()")

	netblob := tH.Marshal()

	fmt.Printf("\n\tTCPHeadr reference blob:\n\t\t[%b]", refblob)
	fmt.Printf("\n\tTCPHeadr struct:\n\t\t[%b]", tH)
	fmt.Printf("\n\tTCPHeadr, marshalled:\n\t\t[%b]", netblob)

	i := 0
	for byt := range netblob {
		fmt.Printf("\n\tNetblob[%d]: %d -- BYTEVAL: %d", i, netblob[i], byt)
		if byt != int(refblob[i]) {
			t.Fatalf("\n\t(*TCPHeadr).Marshal(): FAIL: Marshalled TCP header value at position %d = %q, want: %v\n========================================", i, byt, int(refblob[i]))
		}
		i++
	}
	fmt.Print("\n\n(*TCPHeadr).Marshal(): PASS!\n========================================")
}
