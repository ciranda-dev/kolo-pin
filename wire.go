package pin

import (
	"errors"
	"fmt"
	"io"
	"time"

	kolocodec "github.com/ciranda-dev/kolo-codec"
	kololog "github.com/ciranda-dev/kolo-log"
)

const (
	// MaxRequestSize is the largest request a pinning peer reads: an ADD with a capability of MaxLogs logs.
	MaxRequestSize = 1 + 1 + kololog.LogIDSize + 2 + MaxCapabilitySize
	// Timeout bounds reading one request and writing one answer.
	Timeout = 60 * time.Second

	maxAnswerSize = 1 + 1 + 4*10
)

// Request types.
const (
	tAdd    = 1
	tRemove = 2
	tStatus = 3
	tRevoke = 4
)

// Answer codes; 0 is success.
const (
	codeOK = iota
	codeNotFound
	codeUnauthorized
	codeExpired
	codeRevoked
	codeQuota
	codeDiskFull
	codeInvalid
	codeTooLarge
	codeBusy
	codeProtocol
	codeOwnerLimit
	codeMax = codeOwnerLimit
)

var codeErrs = [...]error{nil, ErrNotFound, ErrUnauthorized, ErrExpired, ErrRevoked, ErrQuotaExceeded,
	ErrDiskFull, ErrInvalid, ErrTooLarge, ErrBusy, ErrProtocol, ErrOwnerLimit}

type request struct {
	typ   uint64
	logID kololog.LogID
	data  []byte // capability for tAdd, revoke note for tRevoke
}

func (r request) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutUvarint(r.typ)
	switch r.typ {
	case tAdd:
		e.PutFixed(r.logID[:])
		e.PutBytes(r.data)
	case tRemove, tStatus:
		e.PutFixed(r.logID[:])
	case tRevoke:
		e.PutBytes(r.data)
	}
	return e.Bytes()
}

func decodeRequest(b []byte) (request, error) {
	var r request
	d := kolocodec.NewDecoder(b)
	v, err := d.Uvarint()
	if err != nil || v != 0 {
		return r, ErrProtocol
	}
	if r.typ, err = d.UvarintMax(tRevoke); err != nil || r.typ == 0 {
		return r, ErrProtocol
	}
	if r.typ != tRevoke {
		id, err := d.Fixed(kololog.LogIDSize)
		if err != nil {
			return r, ErrProtocol
		}
		copy(r.logID[:], id)
	}
	if r.typ == tAdd || r.typ == tRevoke {
		if r.data, err = d.Bytes(MaxCapabilitySize); err != nil {
			return r, ErrProtocol
		}
	}
	if d.Done() != nil {
		return r, ErrProtocol
	}
	return r, nil
}

// answer is a code and, for a successful ADD or STATUS, the log's Info.
type answer struct {
	code uint64
	info *Info
}

func (a answer) encode() []byte {
	var e kolocodec.Encoder
	e.PutUvarint(0)
	e.PutUvarint(a.code)
	if a.info != nil {
		e.PutUvarint(a.info.Entries)
		e.PutUvarint(a.info.Used)
		e.PutUvarint(a.info.Quota)
		e.PutUvarint(uint64(a.info.Expires.Unix()))
	}
	return e.Bytes()
}

func decodeAnswer(b []byte, withInfo bool) (Info, error) {
	d := kolocodec.NewDecoder(b)
	v, err := d.Uvarint()
	if err != nil || v != 0 {
		return Info{}, ErrProtocol
	}
	code, err := d.UvarintMax(codeMax)
	if err != nil {
		return Info{}, ErrProtocol
	}
	if code != codeOK {
		if d.Done() != nil {
			return Info{}, ErrProtocol
		}
		return Info{}, codeErrs[code]
	}
	var in Info
	if withInfo {
		var exp uint64
		var errs [4]error
		in.Entries, errs[0] = d.Uvarint()
		in.Used, errs[1] = d.Uvarint()
		in.Quota, errs[2] = d.Uvarint()
		exp, errs[3] = d.UvarintMax(maxTime)
		if firstErr(errs[:]...) != nil {
			return Info{}, ErrProtocol
		}
		in.Expires = time.Unix(int64(exp), 0)
	}
	if d.Done() != nil {
		return Info{}, ErrProtocol
	}
	return in, nil
}

// readAll reads a whole stream of at most max bytes, ErrTooLarge past it.
func readAll(r io.Reader, max int) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, int64(max)+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	if len(b) > max {
		return nil, ErrTooLarge
	}
	return b, nil
}

// codeOf maps an error to the answer code a pinning peer sends.
func codeOf(err error) uint64 {
	for c, e := range codeErrs {
		if e != nil && errors.Is(err, e) {
			return uint64(c)
		}
	}
	return codeBusy
}
