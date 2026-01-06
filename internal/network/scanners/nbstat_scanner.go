package scanners

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

/*
	The NetBIOS NBSTAT request and response formats are detailed in RFC 1002.
	--------------------------------------------------------
	The request packet consists of: header, name, query type, query class as follows:

	HEADER:
	NAME_TRN_ID  (2 bytes)  Transaction ID
	Flags        (2 bytes)
	QDCOUNT      (2 bytes)  Number of questions (1)
	ANCOUNT      (2 bytes)  Number of answers (0)
	NSCOUNT      (2 bytes)
	ARCOUNT      (2 bytes)
	6 bytes total

	NAME: variable length

	QUESTION_TYPE   (2 bytes)  0x0021 for NBSTAT
	QUESTION_CLASS  (2 bytes)  0x0001 for Internet class
	--------------------------------------------------------
	The response packet consists of: header, request name, query type, query class,
	answer section, RDATA section(s), statistics:

	HEADER:
	NAME_TRN_ID  (2 bytes)  Transaction ID
	Flags        (2 bytes)
	QDCOUNT      (2 bytes)  Number of questions (0)
	ANCOUNT      (2 bytes)  Number of answers (1)
	NSCOUNT      (2 bytes)
	ARCOUNT      (2 bytes)
	12 bytes total

	RR_NAME: the requesting name, variable length, usually the same as in the request.

	RR_TYPE   (2 bytes)  0x0021 for NBSTAT
	RR_CLASS  (2 bytes)  0x0001 for Internet class
	    // Down to here we expect the same data as in the request,
	    // except of flags and QDCOUNT/ANCOUNT values.

	TTL       (4 bytes)  Record validity period
	RDLENGTH  (2 bytes)  Number of bytes in the following RDATA section

	RDATA:
	NUM_NAMES (1 byte)   Number of entries in this section
	NODE_NAME (16 bytes) 15-byte name, padded with spaces, and 1-byte suffix:
	                     00 - workstation etc. (https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-brws/0c773bdd-78e2-4d8b-8b3d-b7506849847b)
	NAME_FLAGS (2 bytes) see RFC 1002 4.2.18. We are interested only in the leftmost bit:
	                     1 for group name, 0 for machine name.

	    // name and flags may be repeated if NUM_NAMES > 1
		// or may be absent if NUM_NAMES == 0

	STATISTICS:
	UNIT_ID   Unique ID - usually it's the MAC address; 6 bytes in this case
	other entries...
*/

var requestBlobe = []byte{
	0x13, 0x37, // Transaction ID
	0x00, 0x00, // Flags
	0x00, 0x01, // QDCOUNT
	0x00, 0x00, // ANCOUNT
	0x00, 0x00,
	0x00, 0x00,

	// Encoded NetBIOS name: "*"
	0x20,
	0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
	0x00,

	0x00, 0x21, // Type: NBSTAT
	0x00, 0x01, // Class: IN
}

var msBrwsGroup = []byte{
	0x01, 0x02, 0x5F, 0x5F, 0x4D, 0x53, 0x42, 0x52,
	0x4F, 0x57, 0x53, 0x45, 0x5F, 0x5F, 0x02, //0x01, - checked as suffix
}

type NbstatScanner struct {
	dialer    *net.Dialer
	bytesPool *sync.Pool
}

func NewNbstatScanner() *NbstatScanner {
	return &NbstatScanner{
		dialer: &net.Dialer{
			KeepAlive: -1,
		},
		bytesPool: &sync.Pool{
			New: func() any {
				return make([]byte, 512)
			},
		},
	}
}

func (s *NbstatScanner) GetName() string {
	return "NBSTAT Probe"
}

func (s *NbstatScanner) ScanTimeout(ctx context.Context, target *TargetInfo, timeout time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		if !target.Address.Is4() {
			return errors.New("NetBIOS NBSTAT is only supported for IPv4")
		}
		context, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		addr := net.JoinHostPort(target.Address.String(), "137")
		conn, err := s.dialer.DialContext(context, "udp4", addr)
		if err != nil {
			return nil
		}
		conn.SetDeadline(time.Now().Add(timeout))
		defer conn.Close()
		_, err = conn.Write(requestBlobe)
		if err != nil {
			return err
		}
		buf := s.bytesPool.Get().([]byte)
		defer s.bytesPool.Put(buf)
		n, err := conn.Read(buf)
		if err != nil {
			return err
		}
		target.SetState(HostAlive)
		if n > 0 {
			return s.parseNbstatResponse(buf[:n], target)
		}

		return nil
	}
}

func (s *NbstatScanner) parseNbstatResponse(buf []byte, target *TargetInfo) error {
	// index of the last byte in the buffer
	last := len(buf) - 1

	// check header length and contents
	// (we've sent one question and expect one answer)
	if last <= 12 {
		return errors.New("NBNS header too short")
	}
	qdcount := int(binary.BigEndian.Uint16(buf[4:6]))
	ancount := int(binary.BigEndian.Uint16(buf[6:8]))
	if qdcount != 0 || ancount != 1 {
		return errors.New("unexpected NBNS packet content")
	}

	// current position in the buffer
	pos := 12
	// locate the RR_TYPE=0x0021 and RR_CLASS=0x0001 entries
	for {
		if last-pos < 4 {
			return errors.New("failed to parse NBNS packet content")
		}
		val := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
		pos += 2
		if val != 0x0021 {
			continue
		}
		val = int(binary.BigEndian.Uint16(buf[pos : pos+2]))
		pos += 2
		if val == 0x0001 {
			break
		}
	}
	if last-pos < 7 {
		return errors.New("unexpected NBNS packet end")
	}

	// skip TTL
	pos += 4

	rdlength := binary.BigEndian.Uint16(buf[pos : pos+2])
	if rdlength < 16 {
		// the packet contains no answer;
		// however, that's not an error
		return nil
	}
	pos += 2
	numnames := int(buf[pos])
	if numnames == 0 {
		// the packet contains no answer;
		// however, that's not an error
		return nil
	}
	pos += 1
	for range numnames {
		if last-pos < 18 {
			return errors.New("unexpected NBNS packet end")
		}
		// check for workstation name
		suffix := buf[pos+15]
		switch suffix {
		case 0x00:
			// workstation service name
			name := strings.TrimSpace(string(buf[pos : pos+15]))
			flag := buf[pos+16]
			if len(name) > 0 {
				if flag&0x80 != 0 {
					// group name
					target.Workgroup = name
				} else {
					// machine name
					target.HostName = name
				}
				/*
					// TODO use setter for this
					if len(target.HostName) == 0 {
						target.HostName = name
					} else {
						// there's already a name present,
						// but let's save what we received
						target.Comments = append(target.Comments, name)
					}
				*/
			}
		case 0x01:
			// fingerprint MS CIFS Browser Protocol
			if bytes.Equal(buf[pos:pos+15], msBrwsGroup) {
				target.Comments = append(target.Comments, "MS CIFS Browser Protocol (MS-BRWS)")
			}
		}
		pos += 18
	}
	if last-pos >= 5 {
		mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
			buf[pos], buf[pos+1], buf[pos+2], buf[pos+3], buf[pos+4], buf[pos+5],
		)
		if len(target.Mac) == 0 {
			target.Mac = mac
		} else {
			// there's already a MAC present,
			// but let's save what we received
			target.Comments = append(target.Comments, mac)
		}
	}

	return nil
}
