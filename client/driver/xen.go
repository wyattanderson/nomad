package driver

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/nomad/structs"
	// "github.com/hashicorp/nomad/client/driver/executor"
	"github.com/hashicorp/nomad/client/fingerprint"
	"os/exec"
	"regexp"
	// "strings"
)

var (
	reXenInfo = regexp.MustCompile(`(?P<key>\w+)\s+:\s+(?P<value>\S+)`)
)

type XenDriver struct {
	DriverContext
	fingerprint.StaticFingerprinter
}

func NewXenDriver(ctx *DriverContext) Driver {
	return &XenDriver{DriverContext: *ctx}
}

func (d *XenDriver) Fingerprint(cfg *config.Config, node *structs.Node) (bool, error) {
	bin := "xl"

	outBytes, err := exec.Command(bin, "info").Output()
	if err != nil {
		return false, nil
	}

	var xenCfg map[string]string
	scanner := bufio.NewScanner(bytes.NewReader(outBytes))
	for scanner.Scan() {
		matches := reXenInfo.FindStringSubmatch(scanner.Text())
		xenCfg[matches[0]] = matches[1]
	}

	_, ok := xenCfg["xen_version"]
	if !ok {
		return false, fmt.Errorf("Unable to determine Xen version")
	}

	node.Attributes["driver.xen"] = "1"
	for key, value := range xenCfg {
		node.Attributes[fmt.Sprintf("driver.xen.%s", key)] = value
	}

	return true, nil
}

func (d *XenDriver) Open(ctx *ExecContext, handleID string) (DriverHandle, error) {
	return nil, fmt.Errorf("not implemented")
}

func (d *XenDriver) Start(ctx *ExecContext, task *structs.Task) (DriverHandle, error) {
	return nil, fmt.Errorf("not implemented")
}
