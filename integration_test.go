package luks

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/anatol/vmtest"
	"github.com/stretchr/testify/assert"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
)

func compileExamples() error {
	cmd := exec.Command("go", "test", "-c", "examples/end2end_test.go", "-o", "luks_end2end_test")
	if testing.Verbose() {
		log.Print("compile in-qemu test binary")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	return cmd.Run()
}

func withQemu(t *testing.T) {
	t.Parallel()

	// These integration tests use QEMU with a statically-compiled kernel (to avoid inintramfs) and a specially
	// prepared rootfs. See [instructions](https://github.com/anatol/vmtest/blob/master/docs/prepare_image.md)
	// how to prepare these binaries.
	params := []string{"-net", "user,hostfwd=tcp::10022-:22", "-net", "nic", "-m", "8G", "-smp", strconv.Itoa(runtime.NumCPU())}
	if os.Getenv("TEST_DISABLE_KVM") != "1" {
		params = append(params, "-enable-kvm", "-cpu", "host")
	}
	opts := vmtest.QemuOptions{
		OperatingSystem: vmtest.OS_LINUX,
		Kernel:          "bzImage",
		Params:          params,
		Disks:           []vmtest.QemuDisk{{Path: "rootfs.cow", Format: "qcow2"}},
		Append:          []string{"root=/dev/sda", "rw"},
		Verbose:         testing.Verbose(),
		Timeout:         50 * time.Second,
	}
	// Run QEMU instance
	qemu, err := vmtest.NewQemu(&opts)
	assert.NoError(t, err)
	// Shutdown QEMU at the end of the test case
	defer qemu.Shutdown()

	config := &ssh.ClientConfig{
		User:            "root",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, err := ssh.Dial("tcp", "localhost:10022", config)
	assert.NoError(t, err)
	defer conn.Close()

	sess, err := conn.NewSession()
	assert.NoError(t, err)
	defer sess.Close()

	scpSess, err := conn.NewSession()
	assert.NoError(t, err)

	assert.NoError(t, scp.CopyPath("luks_end2end_test", "luks_end2end_test", scpSess))

	testCmd := "./luks_end2end_test -test.parallel " + strconv.Itoa(runtime.NumCPU())
	if testing.Verbose() {
		testCmd += " -test.v"
	}

	output, err := sess.CombinedOutput(testCmd)
	if testing.Verbose() {
		fmt.Print(string(output))
	}
	assert.NoError(t, err)
}

// withRoot runs integration tests at the local host. It requires root permissions.
func withRoot(t *testing.T) {
	t.Parallel()

	args := []string{"./luks_end2end_test", "-test.parallel", strconv.Itoa(runtime.NumCPU())}
	if testing.Verbose() {
		args = append(args, "-test.v")
	}
	cmd := exec.Command("sudo", args...)
	if testing.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	}
	assert.NoError(t, cmd.Run())
}

func TestIntegration(t *testing.T) {
	assert.NoError(t, compileExamples())
	//defer os.Remove("luks_end2end_test")

	t.Run("Qemu", withQemu)
	t.Run("Root", withRoot)
}
