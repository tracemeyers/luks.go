package luks

import (
	"encoding/base64"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Must be at least 2 sectors in size so we verify the sector number input to
// xts works as expected.
const encryptedContainerSize = int64(1024)
const encryptedContainerB64 = `lGveDOTL0XJmq2hijUxhoFDQfc+7LI7GHIbxCAlqT+7DSlZPeZBmbxCPGh7Cjy8qF9oa/BTYZTdZ
7985WyiZiWeaQ58TExBCdYyjDGtUEyb8T41DUVNhpmubcHFgSXEZbPCl7NK7qPZGg+XYIyd20Oc3
tlMHVMwI2brJYJRl7OKMO1CvX89VRRQEcHDRACq2iOYXXiTtoCAd1bX96hGXh9yOUdqQxsr51Lvh
i/nAlQ53n666DG18QTOwJgJJ7HP6CGsb+ixs4mtJl2+YHA9AGn4Oj68WuJwLsr4RlmjtuU4OXWBw
TxlexM8j7Fj5PIOxvzz2WMhwpB3rLC0Vf5Ow8rV42oAELhc2nU1Hj6JLubUei54Gx8uRUFL18n1h
PTqPUbR08Tjc12/4SQ/4SjedxFqIu4Dz8VMZeX4IR2UO3cxsTrvZd+Ku5XnanAX0Q5+yjC5IZXru
xks3mqAp0vYiqTFZ4Yyvn0b3YavvUleB7+SGb7CqWZVm/zQMu4iUsqOqoEWfyFEWupET0JkoE0w+
wG65Dh/TaErV3jDN14l0T39PVl0CbompDaFKSG6ItSfKJ0R+ygyfyox/RMInk+fA/g7soxAAVvgW
W+baeIMpbW9npuAy/tGIXNZxg5UNz9s1YuY5ILQ8k4RlrBQeKTHwETe2IiQ/0w9eWS3xQexwcmu+
HgdoHgqiA6B3LcQ3SKA0cS8bQEXsb9PSA2AIItj71TUEt5n2fyM+SP9+ia2rXJavIS90uZg6eB3j
oy+4oTISvCy2V1k/CRXTkhje2V98JvwMds1sIrUh6gP3T2gd4OPv1YB38T7NTBxZrDKVjC0qYQY/
hC5HDUhxiLAaZOtsGKdB/ILdDtZoaLS/xfjenaNMPm2rYvv1bipEXhxnkrTrbkpNqxaaEcsgVqlp
dtTzZ+7aJGDrnllKr/ypWIWmbGSMRBVf8ifVcXtYZ8HvPp3KQKt8yNsIehgZV+r4VOM8+kgUEQEo
K4gET7hrq6nxg+kXFvp1RGInJNyDFPhpEFIFzXDH18L0uUg+m95wOJahg1ax3U0ckptw/yInjwyv
kTWNoz1yFO/BySjA+Vj9hWCh8ba8LqCNlybfPiS/HtjwN5t1caHwXxNOBD40jIDBe603IAY3Kf3I
tz1Es6YaZ4u4h8VrCV11+NbEV/pT5/3uO/zAX9rYkI1jhl+TRCCLPTwbId3ra5PzHpVeUJR4nsWJ
Wq0yDZ8OCsPAm3adpKyGhm3TiAAGAvpNd0qijet3Ayi9jr97c6AjwP97vm4GD7sZsMRAdps7Xszu
ZU6V8LR78fSj50jeXT3FNj4IIkzkmRMOAzTht7h8gPcu6giXmO6I2blhB8gVW5acJgzGUJ9Eyw==
`

// The test volume is initialized with all zeros. The test image was created
// like so:
//
//	 # generated using `head -c 64 /dev/random | base64`
//   $ echo -n 'bmUrTm9ZSElSWE1URFhaYmVUVTNpaTZNZFRVMVJFZHZZazYwSldjU0E4aEZURXo3aTRIdTZzSGNDNEZaRkVOaQ==' | base64 -d > mk
//
//   # 2MB + 1024 (so 1k of available space, must be at least 2 sectors to verify xts)
//	 $ truncate -s $(expr 2097152 + 1024) test.img
//
//   $ echo -n 'foobar' | cryptsetup luksFormat --type luks1 --iter-time 5 -q --master-key-file mk test.img
//	 $ echo -n 'foobar' | cryptsetup luksDump --dump-master-key --master-key-file mk.test test.img
//	 $ diff mk mk.test
//
//   $ echo -n 'foobar' | sudo cryptsetup luksOpen test.img TestVolumeReaderReadAt
//	 $ sudo sh -c 'dd if=/dev/zero bs=512 count=2 > /dev/mapper/TestVolumeReaderReadAt'
//	 $ sudo cryptsetup luksClose TestVolumeReaderReadAt
//
//   # Dump the encrypted container
//   $ tail -c 1024 test.img | base64
func preparePredictableLuks1Disk(t *testing.T) (*os.File, string) {
	headerSize := int64(2 * 1024 * 1024)
	password := "foobar"
	mkB64 := `bmUrTm9ZSElSWE1URFhaYmVUVTNpaTZNZFRVMVJFZHZZazYwSldjU0E4aEZURXo3aTRIdTZzSGNDNEZaRkVOaQ==`

	mk, err := base64.StdEncoding.DecodeString(mkB64)
	assert.NoError(t, err)

	mkFile, err := ioutil.TempFile("", "luksv1.go.mk")
	assert.NoError(t, err)
	_, err = mkFile.Write(mk)
	assert.NoError(t, err)
	defer mkFile.Close()
	defer os.Remove(mkFile.Name())

	disk, err := ioutil.TempFile("", "luksv1.go.disk")
	assert.NoError(t, err)
	assert.NoError(t, disk.Truncate(headerSize+encryptedContainerSize))

	args := []string{"luksFormat", "--type", "luks1", "--iter-time", "5", "--master-key-file", mkFile.Name(), "-q", disk.Name()}
	cmd := exec.Command("cryptsetup", args...)

	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	assert.NoError(t, cmd.Run())

	data, err := base64.StdEncoding.DecodeString(encryptedContainerB64)
	assert.NoError(t, err)
	_, err = disk.WriteAt(data, headerSize)
	assert.NoError(t, err)

	return disk, password
}

func TestVolumeReaderReadAt(t *testing.T) {
	t.Parallel()

	disk, password := preparePredictableLuks1Disk(t)
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV1Device(disk.Name(), disk)
	assert.NoError(t, err)

	v, err := d.UnsealVolume(0, []byte(password))
	assert.NoError(t, err)

	r, err := OpenReadVolume(v)
	assert.NoError(t, err)
	defer r.Close()

	b := make([]byte, encryptedContainerSize)
	n, err := r.ReadAt(b, 0)
	assert.NoError(t, err)
	assert.Equal(t, len(b), n)

	expected := make([]byte, encryptedContainerSize)
	assert.EqualValues(t, expected, b)

	err = r.Close()
	assert.NoError(t, err)
}
