package dnp3

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// Sequential file transfer objects (group 70, Annex A.27; procedures in
// 4.4.17 to 4.4.19 and 5.3). Every variation travels with an object size
// prefix (qualifier 0x5B); these types are the object data.

// File operational modes of a file command (g70v3).
const (
	FileModeNone   = 0 // delete, get info
	FileModeRead   = 1
	FileModeWrite  = 2
	FileModeAppend = 3
)

// File status codes (g70v4, g70v6).
var fileStatusNames = map[uint8]string{
	0: "success", 1: "permission-denied", 2: "invalid-mode", 3: "file-not-found", 4: "file-locked",
	5: "too-many-open", 6: "invalid-handle", 7: "write-block-size", 8: "comm-lost", 9: "cannot-abort",
	16: "not-opened", 17: "handle-expired", 18: "buffer-overrun", 19: "fatal", 20: "block-sequence",
	255: "undefined",
}

// FileStatusName names a file status code.
func FileStatusName(s uint8) string {
	if n, ok := fileStatusNames[s]; ok {
		return n
	}
	return fmt.Sprintf("status-%d", s)
}

// FileCommand is g70v3: open or delete a file.
type FileCommand struct {
	Created     time.Time
	Permissions uint16
	AuthKey     uint32
	Size        uint32
	Mode        uint16
	MaxBlock    uint16
	RequestID   uint16
	Name        string
}

const fileCommandFixed = 26

// Encode is the object data (the name follows the fixed fields).
func (c FileCommand) Encode() []byte {
	out := binary.LittleEndian.AppendUint16(nil, fileCommandFixed)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(c.Name)))
	out = appendTimeOrZero(out, c.Created)
	out = binary.LittleEndian.AppendUint16(out, c.Permissions)
	out = binary.LittleEndian.AppendUint32(out, c.AuthKey)
	out = binary.LittleEndian.AppendUint32(out, c.Size)
	out = binary.LittleEndian.AppendUint16(out, c.Mode)
	out = binary.LittleEndian.AppendUint16(out, c.MaxBlock)
	out = binary.LittleEndian.AppendUint16(out, c.RequestID)
	return append(out, c.Name...)
}

// ParseFileCommand decodes g70v3 object data.
func ParseFileCommand(b []byte) (FileCommand, error) {
	if len(b) < fileCommandFixed {
		return FileCommand{}, errors.New("g70v3 too short")
	}
	name, err := stringAt(b, binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]))
	if err != nil {
		return FileCommand{}, fmt.Errorf("g70v3: %w", err)
	}
	return FileCommand{
		Created: timeOrZero(b[4:]), Permissions: binary.LittleEndian.Uint16(b[10:]), AuthKey: binary.LittleEndian.Uint32(b[12:]),
		Size: binary.LittleEndian.Uint32(b[16:]), Mode: binary.LittleEndian.Uint16(b[20:]), MaxBlock: binary.LittleEndian.Uint16(b[22:]),
		RequestID: binary.LittleEndian.Uint16(b[24:]), Name: name,
	}, nil
}

// FileStatus is g70v4: the answer to open, close, delete and abort, and
// the request of close and abort.
type FileStatus struct {
	Handle    uint32
	Size      uint32
	MaxBlock  uint16
	RequestID uint16
	Status    uint8
	Text      string
}

// Encode is the object data.
func (s FileStatus) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, s.Handle)
	out = binary.LittleEndian.AppendUint32(out, s.Size)
	out = binary.LittleEndian.AppendUint16(out, s.MaxBlock)
	out = binary.LittleEndian.AppendUint16(out, s.RequestID)
	return append(append(out, s.Status), s.Text...)
}

// ParseFileStatus decodes g70v4 object data.
func ParseFileStatus(b []byte) (FileStatus, error) {
	if len(b) < 13 {
		return FileStatus{}, errors.New("g70v4 too short")
	}
	return FileStatus{Handle: binary.LittleEndian.Uint32(b), Size: binary.LittleEndian.Uint32(b[4:]), MaxBlock: binary.LittleEndian.Uint16(b[8:]),
		RequestID: binary.LittleEndian.Uint16(b[10:]), Status: b[12], Text: string(b[13:])}, nil
}

// FileTransport is g70v5: a block of file data. Block numbers start at 0;
// Last marks the final block (bit 31 of the block field).
type FileTransport struct {
	Handle uint32
	Block  uint32
	Last   bool
	Data   []byte
}

func blockField(block uint32, last bool) uint32 {
	v := block & 0x7FFFFFFF
	if last {
		v |= 1 << 31
	}
	return v
}

// Encode is the object data.
func (t FileTransport) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, t.Handle)
	out = binary.LittleEndian.AppendUint32(out, blockField(t.Block, t.Last))
	return append(out, t.Data...)
}

// ParseFileTransport decodes g70v5 object data.
func ParseFileTransport(b []byte) (FileTransport, error) {
	if len(b) < 8 {
		return FileTransport{}, errors.New("g70v5 too short")
	}
	bl := binary.LittleEndian.Uint32(b[4:])
	return FileTransport{Handle: binary.LittleEndian.Uint32(b), Block: bl & 0x7FFFFFFF, Last: bl&(1<<31) != 0, Data: append([]byte(nil), b[8:]...)}, nil
}

// FileTransportStatus is g70v6: the status of a file data transfer.
type FileTransportStatus struct {
	Handle uint32
	Block  uint32
	Last   bool
	Status uint8
	Text   string
}

// Encode is the object data.
func (t FileTransportStatus) Encode() []byte {
	out := binary.LittleEndian.AppendUint32(nil, t.Handle)
	out = binary.LittleEndian.AppendUint32(out, blockField(t.Block, t.Last))
	return append(append(out, t.Status), t.Text...)
}

// ParseFileTransportStatus decodes g70v6 object data.
func ParseFileTransportStatus(b []byte) (FileTransportStatus, error) {
	if len(b) < 9 {
		return FileTransportStatus{}, errors.New("g70v6 too short")
	}
	bl := binary.LittleEndian.Uint32(b[4:])
	return FileTransportStatus{Handle: binary.LittleEndian.Uint32(b), Block: bl & 0x7FFFFFFF, Last: bl&(1<<31) != 0, Status: b[8], Text: string(b[9:])}, nil
}

// FileDescriptor is g70v7: file information (GET_FILE_INFO, directory
// entries). Type 0 is a directory, 1 a simple file.
type FileDescriptor struct {
	Type        uint16
	Size        uint32
	Created     time.Time
	Permissions uint16
	RequestID   uint16
	Name        string
}

const fileDescriptorFixed = 20

// Encode is the object data.
func (d FileDescriptor) Encode() []byte {
	out := binary.LittleEndian.AppendUint16(nil, fileDescriptorFixed)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(d.Name)))
	out = binary.LittleEndian.AppendUint16(out, d.Type)
	out = binary.LittleEndian.AppendUint32(out, d.Size)
	out = appendTimeOrZero(out, d.Created)
	out = binary.LittleEndian.AppendUint16(out, d.Permissions)
	out = binary.LittleEndian.AppendUint16(out, d.RequestID)
	return append(out, d.Name...)
}

// ParseFileDescriptor decodes g70v7 object data.
func ParseFileDescriptor(b []byte) (FileDescriptor, error) {
	if len(b) < fileDescriptorFixed {
		return FileDescriptor{}, errors.New("g70v7 too short")
	}
	name, err := stringAt(b, binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]))
	if err != nil {
		return FileDescriptor{}, fmt.Errorf("g70v7: %w", err)
	}
	return FileDescriptor{Type: binary.LittleEndian.Uint16(b[4:]), Size: binary.LittleEndian.Uint32(b[6:]), Created: timeOrZero(b[10:]),
		Permissions: binary.LittleEndian.Uint16(b[16:]), RequestID: binary.LittleEndian.Uint16(b[18:]), Name: name}, nil
}

// ParseDirectory splits the content of a directory file into its g70v7
// entries (5.3: each entry is a descriptor preceded by nothing; the
// descriptors follow each other).
func ParseDirectory(b []byte) ([]FileDescriptor, error) {
	var out []FileDescriptor
	for len(b) > 0 {
		if len(b) < fileDescriptorFixed {
			return out, errors.New("directory entry truncated")
		}
		n := int(binary.LittleEndian.Uint16(b)) + int(binary.LittleEndian.Uint16(b[2:]))
		if n < fileDescriptorFixed || len(b) < n {
			return out, errors.New("directory entry truncated")
		}
		d, err := ParseFileDescriptor(b[:n])
		if err != nil {
			return out, err
		}
		out = append(out, d)
		b = b[n:]
	}
	return out, nil
}

// FileAuth is g70v2: a request for (and the answer with) a file
// authentication key.
type FileAuth struct {
	User, Password string
	Key            uint32
}

// Encode is the object data.
func (a FileAuth) Encode() []byte {
	// An absent string has offset 0 (the outstation's answer, EX 4-34).
	uo, po := uint16(0), uint16(0)
	if a.User != "" {
		uo = 12
	}
	if a.Password != "" {
		po = uint16(12 + len(a.User))
	}
	out := binary.LittleEndian.AppendUint16(nil, uo)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(a.User)))
	out = binary.LittleEndian.AppendUint16(out, po)
	out = binary.LittleEndian.AppendUint16(out, uint16(len(a.Password)))
	out = binary.LittleEndian.AppendUint32(out, a.Key)
	return append(append(out, a.User...), a.Password...)
}

// ParseFileAuth decodes g70v2 object data.
func ParseFileAuth(b []byte) (FileAuth, error) {
	if len(b) < 12 {
		return FileAuth{}, errors.New("g70v2 too short")
	}
	u, err := stringAt(b, binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:]))
	if err != nil {
		return FileAuth{}, fmt.Errorf("g70v2: %w", err)
	}
	p, err := stringAt(b, binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]))
	if err != nil {
		return FileAuth{}, fmt.Errorf("g70v2: %w", err)
	}
	return FileAuth{User: u, Password: p, Key: binary.LittleEndian.Uint32(b[8:])}, nil
}

func stringAt(b []byte, off, n uint16) (string, error) {
	if n == 0 {
		return "", nil
	}
	if int(off)+int(n) > len(b) {
		return "", errors.New("string beyond the object")
	}
	return string(b[off : int(off)+int(n)]), nil
}

func appendTimeOrZero(out []byte, t time.Time) []byte {
	if t.IsZero() {
		return append(out, 0, 0, 0, 0, 0, 0)
	}
	return AppendTime48(out, t)
}

func timeOrZero(b []byte) time.Time {
	t := Time48(b)
	if t.UnixMilli() == 0 {
		return time.Time{}
	}
	return t
}

// FileClient runs the master's side of sequential file transfer (5.3) on
// an association. Objects the outstation returns later as events are
// collected by polling classes 1 to 3; Other receives every fragment of
// those polls so their other data is not lost.
type FileClient struct {
	M        *Master
	MaxBlock uint16        // largest block accepted; default 1024
	Wait     time.Duration // how long to poll for a delayed answer; default 10 s
	Other    func(Fragment)
	User     string // with Password: AUTHENTICATE_FILE before open and delete
	Password string
	reqID    uint16
}

// fileAnswer sends a request and returns the first g70 object of one of
// the wanted variations, polling for class events while the outstation
// answers with a null response.
func (c *FileClient) fileAnswer(ctx context.Context, fc byte, objects []byte, want ...uint8) (uint8, []byte, error) {
	frags, err := c.M.Request(ctx, fc, objects)
	if err != nil {
		return 0, nil, err
	}
	wait := c.Wait
	if wait <= 0 {
		wait = 10 * time.Second
	}
	deadline := time.Now().Add(wait)
	for {
		for _, f := range frags {
			blocks, _ := ParseObjects(f.Objects, true)
			for _, b := range blocks {
				if b.Header.Group == 70 && len(b.Points) > 0 && slicesContains(want, b.Header.Var) {
					return b.Header.Var, b.Points[0].Raw, nil
				}
			}
		}
		if time.Now().After(deadline) {
			return 0, nil, fmt.Errorf("%w: the outstation did not report the %s result within %s", ErrTimeout, FuncName(fc), wait)
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
		frags, err = c.M.Request(ctx, FCRead, ClassRequest(1, 2, 3))
		if err != nil {
			return 0, nil, err
		}
		if c.Other != nil {
			for _, f := range frags {
				c.Other(f)
			}
		}
	}
}

func slicesContains(s []uint8, v uint8) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func (c *FileClient) authKey(ctx context.Context) (uint32, error) {
	if c.User == "" && c.Password == "" {
		return 0, nil
	}
	_, raw, err := c.fileAnswer(ctx, FCAuthenticateFile, fileObj(2, FileAuth{User: c.User, Password: c.Password}.Encode()), 2)
	if err != nil {
		return 0, fmt.Errorf("file authentication: %w", err)
	}
	a, err := ParseFileAuth(raw)
	if err != nil {
		return 0, err
	}
	if a.Key == 0 {
		return 0, errors.New("file authentication: the outstation granted no key (permission denied)")
	}
	return a.Key, nil
}

func fileObj(v uint8, data []byte) []byte {
	b, _ := EncodeBlock(70, v, QFreeFormat, []Point{{Raw: data}})
	return b
}

func (c *FileClient) open(ctx context.Context, name string, mode uint16, size uint32) (FileStatus, error) {
	key, err := c.authKey(ctx)
	if err != nil {
		return FileStatus{}, err
	}
	c.reqID++
	mb := c.MaxBlock
	if mb == 0 {
		mb = 1024
	}
	cmd := FileCommand{Permissions: 0x01FF, AuthKey: key, Size: size, Mode: mode, MaxBlock: mb, RequestID: c.reqID, Name: name}
	if mode != FileModeRead {
		cmd.Created = time.Now()
	}
	_, raw, err := c.fileAnswer(ctx, FCOpenFile, fileObj(3, cmd.Encode()), 4)
	if err != nil {
		return FileStatus{}, fmt.Errorf("opening %s: %w", name, err)
	}
	st, err := ParseFileStatus(raw)
	if err != nil {
		return st, err
	}
	if st.Status != 0 || st.Handle == 0 {
		return st, fmt.Errorf("opening %s: %s", name, FileStatusName(st.Status))
	}
	return st, nil
}

func (c *FileClient) close(ctx context.Context, st FileStatus, abort bool) error {
	fc := byte(FCCloseFile)
	if abort {
		fc = FCAbortFile
	}
	_, raw, err := c.fileAnswer(ctx, fc, fileObj(4, FileStatus{Handle: st.Handle, RequestID: st.RequestID}.Encode()), 4)
	if err != nil {
		return err
	}
	r, err := ParseFileStatus(raw)
	if err == nil && r.Status != 0 {
		err = fmt.Errorf("%s: %s", FuncName(fc), FileStatusName(r.Status))
	}
	return err
}

// ReadFile opens, reads block by block until the last and closes a file.
func (c *FileClient) ReadFile(ctx context.Context, name string) ([]byte, error) {
	st, err := c.open(ctx, name, FileModeRead, 0)
	if err != nil {
		return nil, err
	}
	var out []byte
	for block := uint32(0); ; block++ {
		req := AppendHeader(nil, 70, 5, QFreeFormat, 1, 0)
		obj := FileTransport{Handle: st.Handle, Block: block}.Encode()
		req = binary.LittleEndian.AppendUint16(req, uint16(len(obj)))
		req = append(req, obj...)
		v, raw, err := c.fileAnswer(ctx, FCRead, req, 5, 6)
		if err != nil {
			_ = c.close(ctx, st, true)
			return nil, fmt.Errorf("reading %s: %w", name, err)
		}
		if v == 6 {
			ts, _ := ParseFileTransportStatus(raw)
			return nil, fmt.Errorf("reading %s block %d: %s", name, block, FileStatusName(ts.Status))
		}
		t, err := ParseFileTransport(raw)
		if err != nil {
			_ = c.close(ctx, st, true)
			return nil, err
		}
		if t.Handle != st.Handle {
			_ = c.close(ctx, st, true)
			return nil, fmt.Errorf("reading %s: the answer is for handle %d", name, t.Handle)
		}
		if t.Block != block {
			c.M.cfg.Log.Warn("DNP3 file block number differs from the one requested", "file", name, "requested", block, "got", t.Block)
		}
		if len(t.Data) > int(st.MaxBlock) && st.MaxBlock > 0 {
			_ = c.close(ctx, st, true)
			return nil, fmt.Errorf("reading %s: a block of %d octets exceeds the negotiated %d", name, len(t.Data), st.MaxBlock)
		}
		out = append(out, t.Data...)
		if t.Last {
			break
		}
	}
	return out, c.close(ctx, st, false)
}

// WriteFile opens a file for writing, sends it block by block (the last
// marked) and closes it.
func (c *FileClient) WriteFile(ctx context.Context, name string, data []byte) error {
	st, err := c.open(ctx, name, FileModeWrite, uint32(len(data)))
	if err != nil {
		return err
	}
	bs := int(st.MaxBlock)
	if bs == 0 {
		bs = 1
	}
	for block, off := uint32(0), 0; ; block++ {
		end := min(off+bs, len(data))
		obj := FileTransport{Handle: st.Handle, Block: block, Last: end == len(data), Data: data[off:end]}.Encode()
		req := binary.LittleEndian.AppendUint16(AppendHeader(nil, 70, 5, QFreeFormat, 1, 0), uint16(len(obj)))
		_, raw, err := c.fileAnswer(ctx, FCWrite, append(req, obj...), 6)
		if err != nil {
			_ = c.close(ctx, st, true)
			return fmt.Errorf("writing %s: %w", name, err)
		}
		ts, err := ParseFileTransportStatus(raw)
		if err != nil || ts.Status != 0 {
			return fmt.Errorf("writing %s block %d: %s", name, block, FileStatusName(ts.Status))
		}
		off = end
		if off == len(data) {
			break
		}
	}
	return c.close(ctx, st, false)
}

// Info returns a file's descriptor (GET_FILE_INFO).
func (c *FileClient) Info(ctx context.Context, name string) (FileDescriptor, error) {
	c.reqID++
	v, raw, err := c.fileAnswer(ctx, FCGetFileInfo, fileObj(7, FileDescriptor{RequestID: c.reqID, Name: name}.Encode()), 7, 4)
	if err != nil {
		return FileDescriptor{}, err
	}
	if v == 4 {
		st, _ := ParseFileStatus(raw)
		return FileDescriptor{}, fmt.Errorf("file information of %s: %s", name, FileStatusName(st.Status))
	}
	return ParseFileDescriptor(raw)
}

// List reads a directory file into its entries.
func (c *FileClient) List(ctx context.Context, dir string) ([]FileDescriptor, error) {
	b, err := c.ReadFile(ctx, dir)
	if err != nil {
		return nil, err
	}
	return ParseDirectory(b)
}

// Delete removes a file.
func (c *FileClient) Delete(ctx context.Context, name string) error {
	key, err := c.authKey(ctx)
	if err != nil {
		return err
	}
	c.reqID++
	_, raw, err := c.fileAnswer(ctx, FCDeleteFile, fileObj(3, FileCommand{AuthKey: key, RequestID: c.reqID, Name: name}.Encode()), 4)
	if err != nil {
		return err
	}
	st, err := ParseFileStatus(raw)
	if err == nil && st.Status != 0 {
		err = fmt.Errorf("deleting %s: %s", name, FileStatusName(st.Status))
	}
	return err
}
