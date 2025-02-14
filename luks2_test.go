package luks

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func prepareLuks2Disk(password string, cryptsetupArgs ...string) (*os.File, error) {
	disk, err := ioutil.TempFile("", "luksv2.go.disk")
	if err != nil {
		return nil, err
	}

	if err := disk.Truncate(24 * 1024 * 1024); err != nil {
		return nil, err
	}

	args := []string{"luksFormat", "--type", "luks2", "--iter-time", "5", "-q", disk.Name()}
	args = append(args, cryptsetupArgs...)
	cmd := exec.Command("cryptsetup", args...)
	cmd.Stdin = strings.NewReader(password)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Run(); err != nil {
		return nil, err
	}

	return disk, nil
}

func runLuks2Test(t *testing.T, keySlot int, cryptsetupArgs ...string) {
	t.Parallel()

	password := "foobar"
	disk, err := prepareLuks2Disk(password, cryptsetupArgs...)
	assert.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	d, err := initV2Device(disk.Name(), disk)
	assert.NoError(t, err)

	uuid, err := blkidUUID(disk.Name())
	assert.NoError(t, err)
	assert.Equal(t, uuid, d.UUID())

	v, err := d.UnsealVolume(keySlot, []byte(password))
	assert.NoError(t, err)
	headerSize := 16777216
	assert.Equal(t, uint64(24*1024*1024-headerSize), v.storageSize)
}

func TestLuks2UnlockBasic(t *testing.T) {
	runLuks2Test(t, 0)
}

func TestLuks2UnlockCustomSectorSize(t *testing.T) {
	runLuks2Test(t, 0, "--sector-size", "2048")
}

func TestLuks2UnlockNonZeroSlotId(t *testing.T) {
	runLuks2Test(t, 4, "--key-slot", "4")
}

func TestLuks2UnlockComplex(t *testing.T) {
	runLuks2Test(t, 0, "--cipher", "aes-xts-plain64", "--key-size", "512", "--iter-time", "2000", "--pbkdf", "argon2id", "--hash", "sha3-512")
}

func TestLuks2Hashes(t *testing.T) {
	// ripemd160 forces use of AF padding
	// It looks like cryptsetup 2.4.0 at Arch Linux defaults to openssl backend that supports blake2b-512 and blake2s-256 only. "blake2b-160", "blake2b-256", "blake2b-384" tests are failing thus disabling it for now.
	hashes := []string{"sha1", "sha224", "sha256", "sha384", "sha512", "sha3-224", "sha3-256", "sha3-384", "sha3-512", "ripemd160", "blake2b-512", "blake2s-256"}
	for _, h := range hashes {
		t.Run(h, func(t *testing.T) {
			runLuks2Test(t, 0, "--hash", h)
		})
	}
}

func TestLuks2UnlockMultipleKeySlots(t *testing.T) {
	t.Parallel()

	password := "barfoo"
	disk, err := prepareLuks2Disk(password)
	assert.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	// now let's add a new keyslot and try to unlock again
	addKeyCmd := exec.Command("cryptsetup", "luksAddKey", "-q", disk.Name())
	password2 := "newpwd"
	addKeyCmd.Stdin = strings.NewReader(password + "\n" + password2)
	if testing.Verbose() {
		addKeyCmd.Stdout = os.Stdout
		addKeyCmd.Stderr = os.Stderr
	}
	assert.NoError(t, addKeyCmd.Run())

	d, err := initV2Device(disk.Name(), disk)
	assert.NoError(t, err)

	_, err = d.UnsealVolume(0, []byte(password))
	assert.NoError(t, err)

	_, err = d.UnsealVolume(1, []byte(password2))
	assert.NoError(t, err)
}

func TestLuks2UnlockWithToken(t *testing.T) {
	t.Parallel()

	password := "foobar"
	disk, err := prepareLuks2Disk(password)
	assert.NoError(t, err)
	defer disk.Close()
	defer os.Remove(disk.Name())

	addTokenCmd := exec.Command("cryptsetup", "token", "import", disk.Name())
	slotID := 0
	payload := fmt.Sprintf(`{"type":"clevis","keyslots":["%d"],"jwe":{"ciphertext":"","encrypted_key":"","iv":"","protected":"test\n","tag":""}}`, slotID)
	addTokenCmd.Stdin = strings.NewReader(payload)
	if testing.Verbose() {
		addTokenCmd.Stdout = os.Stdout
		addTokenCmd.Stderr = os.Stderr
	}
	assert.NoError(t, addTokenCmd.Run())

	d, err := initV2Device(disk.Name(), disk)
	assert.NoError(t, err)

	slots := d.Slots()
	assert.Len(t, slots, 1)
	assert.Equal(t, 0, slots[0])

	tokens, err := d.Tokens()
	assert.NoError(t, err)
	assert.Len(t, tokens, 1)

	tk := tokens[0]
	assert.Equal(t, "clevis", tk.Type)
	assert.Equal(t, []int{0}, tk.Slots)

	expected := `{"type":"clevis","keyslots":["0"],"jwe":{"ciphertext":"","encrypted_key":"","iv":"","protected":"test\n","tag":""}}`
	assert.Equal(t, expected, string(tk.Payload))

	uuid, err := blkidUUID(disk.Name())
	assert.NoError(t, err)
	assert.Equal(t, uuid, d.UUID())

	_, err = d.UnsealVolume(0, []byte(password))
	assert.NoError(t, err)
}
