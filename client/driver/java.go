package driver

import (
	"bytes"
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/hashicorp/nomad/client/allocdir"
	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/client/driver/executor"
	"github.com/hashicorp/nomad/client/fingerprint"
	"github.com/hashicorp/nomad/client/getter"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/mitchellh/mapstructure"
)

// JavaDriver is a simple driver to execute applications packaged in Jars.
// It literally just fork/execs tasks with the java command.
type JavaDriver struct {
	DriverContext
	fingerprint.StaticFingerprinter
}

type javaDriverConfig struct {
	JvmOpts        string `mapstructure:"jvm_options"`
	ArtifactSource string `mapstructure:"artifact_source`
	Checksum       string `mapstructure:"checksum"`
	Args           string `mapstructure:"args"`
}

// javaHandle is returned from Start/Open as a handle to the PID
type javaHandle struct {
	cmd    executor.Executor
	waitCh chan error
	doneCh chan struct{}
}

// NewJavaDriver is used to create a new exec driver
func NewJavaDriver(ctx *DriverContext) Driver {
	return &JavaDriver{DriverContext: *ctx}
}

func (d *JavaDriver) Fingerprint(cfg *config.Config, node *structs.Node) (bool, error) {
	// Only enable if we are root when running on non-windows systems.
	if runtime.GOOS == "linux" && syscall.Geteuid() != 0 {
		d.logger.Printf("[DEBUG] driver.java: must run as root user on linux, disabling")
		return false, nil
	}

	// Find java version
	var out bytes.Buffer
	var erOut bytes.Buffer
	cmd := exec.Command("java", "-version")
	cmd.Stdout = &out
	cmd.Stderr = &erOut
	err := cmd.Run()
	if err != nil {
		// assume Java wasn't found
		return false, nil
	}

	// 'java -version' returns output on Stderr typically.
	// Check stdout, but it's probably empty
	var infoString string
	if out.String() != "" {
		infoString = out.String()
	}

	if erOut.String() != "" {
		infoString = erOut.String()
	}

	if infoString == "" {
		d.logger.Println("[WARN] driver.java: error parsing Java version information, aborting")
		return false, nil
	}

	// Assume 'java -version' returns 3 lines:
	//    java version "1.6.0_36"
	//    OpenJDK Runtime Environment (IcedTea6 1.13.8) (6b36-1.13.8-0ubuntu1~12.04)
	//    OpenJDK 64-Bit Server VM (build 23.25-b01, mixed mode)
	// Each line is terminated by \n
	info := strings.Split(infoString, "\n")
	versionString := info[0]
	versionString = strings.TrimPrefix(versionString, "java version ")
	versionString = strings.Trim(versionString, "\"")
	node.Attributes["driver.java"] = "1"
	node.Attributes["driver.java.version"] = versionString
	node.Attributes["driver.java.runtime"] = info[1]
	node.Attributes["driver.java.vm"] = info[2]

	return true, nil
}

func (d *JavaDriver) Start(ctx *ExecContext, task *structs.Task) (DriverHandle, error) {
	var driverConfig javaDriverConfig
	if err := mapstructure.WeakDecode(task.Config, &driverConfig); err != nil {
		return nil, err
	}
	taskDir, ok := ctx.AllocDir.TaskDirs[d.DriverContext.taskName]
	if !ok {
		return nil, fmt.Errorf("Could not find task directory for task: %v", d.DriverContext.taskName)
	}

	// Proceed to download an artifact to be executed.
	path, err := getter.GetArtifact(
		filepath.Join(taskDir, allocdir.TaskLocal),
		driverConfig.ArtifactSource,
		driverConfig.Checksum,
		d.logger,
	)
	if err != nil {
		return nil, err
	}

	jarName := filepath.Base(path)

	// Get the environment variables.
	envVars := TaskEnvironmentVariables(ctx, task)

	args := []string{}
	// Look for jvm options
	jvm_options := driverConfig.JvmOpts
	if jvm_options != "" {
		d.logger.Printf("[DEBUG] driver.java: found JVM options: %s", jvm_options)
		args = append(args, jvm_options)
	}

	// Build the argument list.
	args = append(args, "-jar", filepath.Join(allocdir.TaskLocal, jarName))
	if argRaw := driverConfig.Args; argRaw != "" {
		args = append(args, argRaw)
	}

	// Setup the command
	// Assumes Java is in the $PATH, but could probably be detected
	cmd := executor.Command("java", args...)

	// Populate environment variables
	cmd.Command().Env = envVars.List()

	if err := cmd.Limit(task.Resources); err != nil {
		return nil, fmt.Errorf("failed to constrain resources: %s", err)
	}

	if err := cmd.ConfigureTaskDir(d.taskName, ctx.AllocDir); err != nil {
		return nil, fmt.Errorf("failed to configure task directory: %v", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start source: %v", err)
	}

	// Return a driver handle
	h := &javaHandle{
		cmd:    cmd,
		doneCh: make(chan struct{}),
		waitCh: make(chan error, 1),
	}

	go h.run()
	return h, nil
}

func (d *JavaDriver) Open(ctx *ExecContext, handleID string) (DriverHandle, error) {
	// Find the process
	cmd, err := executor.OpenId(handleID)
	if err != nil {
		return nil, fmt.Errorf("failed to open ID %v: %v", handleID, err)
	}

	// Return a driver handle
	h := &javaHandle{
		cmd:    cmd,
		doneCh: make(chan struct{}),
		waitCh: make(chan error, 1),
	}

	go h.run()
	return h, nil
}

func (h *javaHandle) ID() string {
	id, _ := h.cmd.ID()
	return id
}

func (h *javaHandle) WaitCh() chan error {
	return h.waitCh
}

func (h *javaHandle) Update(task *structs.Task) error {
	// Update is not possible
	return nil
}

func (h *javaHandle) Kill() error {
	h.cmd.Shutdown()
	select {
	case <-h.doneCh:
		return nil
	case <-time.After(5 * time.Second):
		return h.cmd.ForceStop()
	}
}

func (h *javaHandle) run() {
	err := h.cmd.Wait()
	close(h.doneCh)
	if err != nil {
		h.waitCh <- err
	}
	close(h.waitCh)
}
