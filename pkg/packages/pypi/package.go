package pip

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/opencontainers/go-digest"

	"go.linka.cloud/artifact-registry/pkg/buffer"
	"go.linka.cloud/artifact-registry/pkg/storage"
	"go.linka.cloud/artifact-registry/pkg/validation"
)

type Package struct {
	PkgName    string    `json:"name"`
	PkgVersion string    `json:"version"`
	PkgSize    int64     `json:"size"`
	FilePath   string    `json:"filePath"`
	MD5        string    `json:"md5"`
	SHA1       string    `json:"sha1"`
	SHA256     string    `json:"sha256"`
	SHA512     string    `json:"sha512"`
	Metadata   *Metadata `json:"metadata"`

	reader io.ReadCloser
}

type Metadata struct {
	Maintainer   string   `json:"maintainer,omitempty"`
	ProjectURL   string   `json:"projectURL,omitempty"`
	Description  string   `json:"description,omitempty"`
	Dependencies []string `json:"dependencies,omitempty"`
}

func (p *Package) Read(b []byte) (n int, err error) {
	if p.reader == nil {
		return 0, io.EOF
	}
	return p.reader.Read(b)
}

func (p *Package) Close() error {
	if p.reader == nil {
		return nil
	}
	return p.reader.Close()
}

func (p *Package) Name() string {
	return p.PkgName
}

func (p *Package) Path() string {
	return p.FilePath
}

func (p *Package) Version() string {
	return p.PkgVersion
}

func (p *Package) Size() int64 {
	return p.PkgSize
}

func (p *Package) Digest() digest.Digest {
	return digest.NewDigestFromEncoded(digest.SHA256, p.SHA256)
}

func NewPackage(r io.Reader) (*Package, error) {
	buf, err := buffer.CreateHashedBufferFromReader(r)
	if err != nil {
		return nil, err
	}
	md5, sha1, sha256, sha512 := buf.Sums()
	return pkg, err
}
