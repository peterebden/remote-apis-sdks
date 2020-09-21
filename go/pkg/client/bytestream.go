package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"

	"github.com/DataDog/zstd"
	"github.com/bazelbuild/remote-apis-sdks/go/pkg/chunker"

	repb "github.com/bazelbuild/remote-apis/build/bazel/remote/execution/v2"
	bspb "google.golang.org/genproto/googleapis/bytestream"
)

// WriteBytes uploads a byte slice.
func (c *Client) WriteBytes(ctx context.Context, name string, data []byte) error {
	return c.WriteChunked(ctx, name, chunker.NewFromBlob(data, int(c.ChunkMaxSize)))
}

// WriteChunked uploads chunked data with a given resource name to the CAS.
func (c *Client) WriteChunked(ctx context.Context, name string, ch *chunker.Chunker) error {
	cancelCtx, cancel := context.WithCancel(ctx)
	opts := c.RPCOpts()
	defer cancel()
	closure := func() error {
		ch.Reset() // Retry by starting the stream from the beginning.
		// TODO(olaola): implement resumable uploads.

		// Use lower-level Write in order to not retry twice.
		stream, err := c.byteStream.Write(cancelCtx, opts...)
		if err != nil {
			return err
		}
		bsw := &bswriter{
			stream: stream,
			name:   name,
		}
		var w io.Writer = bsw
		if ch.Compressor == repb.Compressor_ZSTD {
			w = zstd.NewWriter(w)
		} else if ch.Compressor != repb.Compressor_IDENTITY {
			return fmt.Errorf("unknown compressor %s", ch.Compressor)
		}
		for ch.HasNext() {
			chunk, err := ch.Next()
			if err != nil {
				return err
			}
			if !ch.HasNext() {
				bsw.finish = true
			}
			_, err = w.Write(chunk.Data)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		if _, err := stream.CloseAndRecv(); err != nil {
			return err
		}
		return nil
	}
	return c.Retrier.Do(cancelCtx, closure)
}

// A bswriter wraps up a bytestream client into an io.Writer.
type bswriter struct {
	stream bspb.ByteStream_WriteClient
	name   string
	offset int64
	finish bool
}

func (w *bswriter) Write(p []byte) (int, error) {
	req := &bspb.WriteRequest{
		WriteOffset: w.offset,
		Data:        p,
		FinishWrite: w.finish,
	}
	if w.offset == 0 {
		req.ResourceName = w.name
	}
	if err := w.stream.Send(req); err != nil {
		return 0, err
	}
	w.offset += int64(len(p))
	return len(p), nil
}

// ReadBytes fetches a resource's contents into a byte slice.
//
// ReadBytes panics with ErrTooLarge if an attempt is made to read a resource with contents too
// large to fit into a byte array.
func (c *Client) ReadBytes(ctx context.Context, name string) ([]byte, error) {
	buf := &bytes.Buffer{}
	_, err := c.readStreamed(ctx, name, 0, 0, buf, repb.Compressor_IDENTITY)
	return buf.Bytes(), err
}

// ReadResourceToFile fetches a resource's contents, saving it into a file.
//
// The provided resource name must be a child resource of this client's instance,
// e.g. '/blobs/abc-123/45' (NOT 'projects/foo/bar/baz').
//
// The number of bytes read is returned.
func (c *Client) ReadResourceToFile(ctx context.Context, name, fpath string) (int64, error) {
	return c.readToFile(ctx, c.InstanceName+name, fpath, repb.Compressor_IDENTITY)
}

func (c *Client) readToFile(ctx context.Context, name string, fpath string, compressor repb.Compressor_Value) (int64, error) {
	f, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, c.RegularMode)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return c.readStreamed(ctx, name, 0, 0, f, compressor)
}

// readStreamed reads from a bytestream and copies the result to the provided Writer, starting
// offset bytes into the stream and reading at most limit bytes (or no limit if limit==0). The
// offset must be non-negative, and an error may be returned if the offset is past the end of the
// stream. The limit must be non-negative, although offset+limit may exceed the length of the
// stream.
func (c *Client) readStreamed(ctx context.Context, name string, offset, limit int64, w io.Writer, compressor repb.Compressor_Value) (n int64, e error) {
	cancelCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	opts := c.RPCOpts()
	closure := func() error {
		// Use lower-level Read in order to not retry twice.
		stream, err := c.byteStream.Read(cancelCtx, &bspb.ReadRequest{
			ResourceName: name,
			ReadOffset:   offset + n,
			ReadLimit:    limit,
		}, opts...)
		if err != nil {
			return err
		}
		bsr := &bsreader{stream: stream}
		var r io.Reader = bsr
		if compressor == repb.Compressor_ZSTD {
			r = zstd.NewReader(r)
		} else if compressor != repb.Compressor_IDENTITY {
			return fmt.Errorf("unknown compressor %s", compressor)
		}
		nm, err := io.Copy(w, r)
		n += int64(nm)
		return err
	}
	e = c.Retrier.Do(cancelCtx, closure)
	return n, e
}

// A bsreader wraps a bytestream read into an io.Reader compatible type
type bsreader struct {
	stream bspb.ByteStream_ReadClient
	buf    []byte
}

func (r *bsreader) Read(p []byte) (int, error) {
	if len(r.buf) == 0 {
		resp, err := r.stream.Recv()
		if err != nil {
			return 0, err
		}
		r.buf = resp.Data
		return r.Read(p)
	} else if len(r.buf) > len(p) {
		copy(p, r.buf)
		r.buf = r.buf[len(p):]
		return len(p), nil
	}
	n := len(r.buf)
	copy(p, r.buf)
	r.buf = nil
	return n, nil
}
