package driver

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
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

type XenInfo map[string]string

func NewXenDriver(ctx *DriverContext) Driver {
	return &XenDriver{DriverContext: *ctx}
}

// We need to override resource fingerprinting here because the default Nomad
// fingerprinting will count the resources in the dom0 which may be limited or
// incorrect.
func (d *XenDriver) fingerprintDom0(node *structs.Node, xen XenInfo) {
	if node.Resources == nil {
		node.Resources = &structs.Resources{}
	}

	cpuMhz, _ := strconv.ParseFloat(xen["cpu_mhz"], 64)
	node.Attributes["cpu.frequency"] = fmt.Sprintf("%.6f", cpuMhz)

	numCores, _ := strconv.ParseInt(xen["nr_cpus"], 10, 32)
	node.Attributes["cpu.numcores"] = fmt.Sprintf("%d", numCores)

	totalCompute := cpuMhz * float64(numCores)
	node.Attributes["cpu.totalcompute"] = fmt.Sprintf("%.6f", totalCompute)
	node.Resources.CPU = int(totalCompute)

	totalMemoryMB, _ := strconv.ParseInt(xen["total_memory"], 10, 32)
	if totalMemoryMB > 0 {
		node.Attributes["memory.totalbytes"] = fmt.Sprintf("%d", totalMemoryMB*1024*1024)
		node.Resources.MemoryMB = int(totalMemoryMB)
	}
}

func (d *XenDriver) Fingerprint(cfg *config.Config, node *structs.Node) (bool, error) {
	bin := "xl"

	outBytes, err := exec.Command(bin, "info").Output()
	if err != nil {
		return false, nil
	}

	xenCfg := make(XenInfo)
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

	d.fingerprintDom0(node, xenCfg)

	return true, nil
}

func (d *XenDriver) Open(ctx *ExecContext, handleID string) (DriverHandle, error) {
	return nil, fmt.Errorf("not implemented")
}

func (d *XenDriver) Start(ctx *ExecContext, task *structs.Task) (DriverHandle, error) {
	return nil, fmt.Errorf("not implemented")
}
