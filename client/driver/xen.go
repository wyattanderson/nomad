package driver

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/client/fingerprint"
	"github.com/hashicorp/nomad/nomad/structs"
)

var (
	reXenInfo = regexp.MustCompile(`(?P<key>\w+)\s+:\s+(?P<value>.+)`)
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

	xenCfg := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(outBytes))
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		matches := reXenInfo.FindStringSubmatch(text)
		if len(matches) != 3 {
			d.logger.Printf("[DEBUG] driver.xen: unexpected xl info output %q", matches)
			continue
		}
		xenCfg[matches[1]] = matches[2]
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
