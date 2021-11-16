package luks

import (
	"crypto/aes"
	"fmt"
	"io"
	"os"

	"github.com/ncw/directio"
	"golang.org/x/crypto/xts"
)

type ReadVolume struct {
	backingFile *os.File
	cipher      *xts.Cipher
	sectorSize  uint64
	offset      int64
	buffer      []byte
}

// OpenReadVolume opens the volume without using dm. Reads decrypt the data.
func OpenReadVolume(v *Volume) (r *ReadVolume, err error) {
	if v.luksType != "LUKS1" {
		return nil, fmt.Errorf("unsupported LUKS type '%s'", v.luksType)
	}
	if v.storageEncryption != "aes-xts-plain64" {
		return nil, fmt.Errorf("unsupported cipher suite '%s'", v.storageEncryption)
	}

	r = &ReadVolume{
		sectorSize: v.storageSectorSize,
		offset:     int64(v.storageOffset),
	}

	r.cipher, err = xts.NewCipher(aes.NewCipher, v.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher; %w", err)
	}

	r.backingFile, err = directio.OpenFile(v.backingDevice, os.O_RDONLY, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open backing device '%s'; %w", v.backingDevice, err)
	}

	return
}

func (r *ReadVolume) ReadAt(p []byte, off int64) (n int, err error) {
	if r.buffer == nil || len(r.buffer) < len(p) {
		r.buffer = directio.AlignedBlock(len(p))
	}

	// The real offset needs to factor in where on disk the encrypted storage
	// starts, not just the caller supplied offset
	readOffset := r.offset + off
	n, err = r.backingFile.ReadAt(r.buffer, readOffset)
	if err != nil && err != io.EOF {
		err = fmt.Errorf("unhandled error occurred while reading raw block device; %w", err)
		return
	}

	sector := uint64(off) / r.sectorSize
	sectorSize := int(r.sectorSize)
	for i := 0; i < n; i += sectorSize {
		ciphertext := r.buffer[i : i+sectorSize]
		plaintext := p[i : i+sectorSize]
		r.cipher.Decrypt(plaintext, ciphertext, sector)
		sector++
	}
	return
}

func (r *ReadVolume) Close() error {
	return r.backingFile.Close()
}
