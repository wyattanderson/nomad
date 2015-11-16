package driver

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/hashicorp/nomad/client/config"
	"github.com/hashicorp/nomad/client/fingerprint"
	"github.com/hashicorp/nomad/nomad/structs"
)

const xenMacPrefix = "00:16:3E"

var (
	reXenInfo    = regexp.MustCompile(`(?P<key>\w+)\s+:\s+(?P<value>.+)`)
	reXenStoreLs = regexp.MustCompile(`/local/domain/(?P<domainId>\d+)/(?P<key>\w+) = "(?P<value>.*)"`)
)

type XenDriver struct {
	DriverContext
	fingerprint.StaticFingerprinter
}

type xenHandle struct {
	domainName string
	logger     *log.Logger
	waitCh     chan error
	doneCh     chan struct{}
}

type xenPid struct {
	domainName string
}

type xenDomainConfig struct {
	Name       string
	CPUCount   int
	Memory     int
	MACAddress string
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
	return nil, fmt.Errorf("open not implemented")
}

func (d *XenDriver) Start(ctx *ExecContext, task *structs.Task) (DriverHandle, error) {
	cfgFile, err := template.ParseFiles("/home/wyatt/test.tmpl")
	if err != nil {
		return nil, fmt.Errorf("Couldn't load config file template")
	}

	// TODO this assumes the allocation ID is random enough to use as
	// a MAC address basis
	hexAllocId := strings.Replace(ctx.AllocID, "-", "", -1)
	macAddress := fmt.Sprintf(
		"%s:%s:%s:%s", xenMacPrefix, hexAllocId[0:2], hexAllocId[2:4], hexAllocId[4:6])

	domainName := fmt.Sprintf("nomad-%s", ctx.AllocID)
	domainConfig := xenDomainConfig{
		Name:       domainName,
		CPUCount:   1, // TODO use the resources
		Memory:     task.Resources.MemoryMB,
		MACAddress: macAddress,
	}

	local, ok := ctx.AllocDir.TaskDirs[task.Name]
	if !ok {
		return nil, fmt.Errorf("No local task dir for %v", task.Name)
	}
	d.logger.Printf("local task dir %s", local)

	cfgFilePath := filepath.Join(local, fmt.Sprintf("nomad-%s.cfg", ctx.AllocID))
	cfgFileHandle, err := os.Create(cfgFilePath)
	if err != nil {
		return nil, err
	}

	// TODO rename all these templates lol
	err = cfgFile.ExecuteTemplate(cfgFileHandle, "test.tmpl", domainConfig)
	if err != nil {
		return nil, err
	}

	h := &xenHandle{
		domainName: domainName,
		logger:     d.logger,
		doneCh:     make(chan struct{}),
		waitCh:     make(chan error, 1),
	}

	xlCmd := exec.Command("xl", "create", cfgFilePath)
	xlCmd.Run()

	go h.run()
	return h, nil
}

func (h *xenHandle) ID() string {
	// TODO do it lol
	panic("fuck")
}

func (h *xenHandle) WaitCh() chan error {
	return h.waitCh
}

func (h *xenHandle) Update(task *structs.Task) error {
	// Update is not possible
	return nil
}

func (h *xenHandle) Kill() error {
	killCmd := exec.Command("xl", "destroy", h.domainName)
	killCmd.Run()

	return nil
}

// TODO this is super hacky but i really don't want to deal with parsing
// xenstore into a tree structure right now for POC sake
func (h *xenHandle) isDomainActive() bool {
	// TODO move this to using libxenlight or xenbus or something as
	// opposed to parsing command output
	outBytes, err := exec.Command("xenstore-ls", "/local/domain", "-f").Output()
	if err != nil {
		panic(err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(outBytes))
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		matches := reXenStoreLs.FindStringSubmatch(text)
		if len(matches) != 4 {
			continue
		}

		if matches[2] == "name" && matches[3] == h.domainName {
			return true
		}
	}

	return false
}

func (h *xenHandle) run() {
	for {
		time.Sleep(5 * time.Second)
		if !h.isDomainActive() {
			break
		}
	}

	close(h.doneCh)
	close(h.waitCh)
}
