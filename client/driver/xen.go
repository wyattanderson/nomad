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
	"syscall"
	"text/template"
	"time"

	"github.com/hashicorp/consul/api"
	"github.com/hashicorp/nomad/client/config"
	cstructs "github.com/hashicorp/nomad/client/driver/structs"
	"github.com/hashicorp/nomad/client/fingerprint"
	"github.com/hashicorp/nomad/nomad/structs"
	"github.com/mitchellh/mapstructure"
)

const xenMacPrefix = "00:16:3E"

type XenDriverConfig struct {
	BaseImagePath string `mapstructure:"base_image_path"`
}

var (
	reXenInfo            = regexp.MustCompile(`(?P<key>\w+)\s+:\s+(?P<value>.+)`)
	reXenStoreLs         = regexp.MustCompile(`/local/domain/(?P<domainId>\d+)/(?P<key>\w+) = "(?P<value>.*)"`)
	reXenStoreDomainName = regexp.MustCompile(`/local/domain/(?P<domainId>\d+)$`)
)

type XenDriver struct {
	DriverContext
	fingerprint.StaticFingerprinter
	xsDomCh chan xsDomInfo
}

type xenHandle struct {
	domainName   string
	consulPrefix string
	logger       *log.Logger
	waitCh       chan *cstructs.WaitResult
	doneCh       chan struct{}
}

type xenPid struct {
	domainName string
}

type xenDomainConfig struct {
	Name       string
	CPUCount   int
	Memory     int
	MACAddress string
	Disks      []string
}

type XenInfo map[string]string

func NewXenDriver(ctx *DriverContext) Driver {
	c := make(chan xsDomInfo)
	go watchXenstore(c)

	driver := &XenDriver{
		DriverContext: *ctx,
		xsDomCh:       c,
	}

	return driver
}

func getKVClient() *api.KV {
	client, err := api.NewClient(api.DefaultConfig())
	if err != nil {
		panic(err)
	}

	kv := client.KV()
	return kv
}

type xsDomInfo struct {
	DomainId   int
	DomainName string
}

func getInstanceInfo(path string, domainId int) xsDomInfo {
	namePath := fmt.Sprintf("%s/name", path)
	outputBytes, err := exec.Command("xenstore-read", namePath).Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			waitStatus := exitError.Sys().(syscall.WaitStatus)
			if waitStatus.ExitStatus() == 1 {
				return xsDomInfo{
					DomainId:   domainId,
					DomainName: "",
				}
			}
		}
	}

	return xsDomInfo{
		DomainId:   domainId,
		DomainName: strings.TrimSpace(string(outputBytes)),
	}
}

// Watches the xenstore to look for domains starting and stopping so that we
// can track job state internally.
func watchXenstore(c chan xsDomInfo) {
	cmd := exec.Command("xenstore-watch", "/local/domain")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}

	cmd.Start()
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		text := strings.TrimSpace(scanner.Text())
		matches := reXenStoreDomainName.FindStringSubmatch(text)
		if len(matches) != 2 {
			continue
		}

		// If we have a match at this point, we've seen a key change
		// for the domain name. Now we check to see if the domain
		// exists. If it doesn't, the domain stopped. If it does, we
		// know the name, from which we can derive the allocation ID.
		domainId, _ := strconv.ParseInt(matches[1], 10, 32)
		xsd := getInstanceInfo(matches[0], int(domainId))
		c <- xsd
	}

	close(c)
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

func (d *XenDriver) qcowImageFromBase(ctx *ExecContext, task *structs.Task, baseImagePath string, allocId string) (string, error) {
	if _, err := os.Stat(baseImagePath); err != nil {
		return "", err
	}

	if task.Resources.DiskMB == 0 {
		return "", fmt.Errorf("Disk resources must be greater than 0")
	}

	local, _ := ctx.AllocDir.TaskDirs[task.Name]
	imagePath := filepath.Join(local, fmt.Sprintf("disk-%s.qcow2", allocId))
	imageSize := fmt.Sprintf("%dM", task.Resources.DiskMB)

	qemuImgCmd := exec.Command(
		"qemu-img", "create", "-b", baseImagePath, "-f", "qcow2",
		"-o", "compat=0.10,backing_fmt=qcow2", imagePath, imageSize)
	d.logger.Printf("qemu cmd: %q", qemuImgCmd.Args)
	err := qemuImgCmd.Run()
	if err != nil {
		return "", err
	}

	return imagePath, nil
}

func (d *XenDriver) Start(ctx *ExecContext, task *structs.Task) (DriverHandle, error) {
	cfgFile, err := template.ParseFiles("/home/wyatt/test.tmpl")
	if err != nil {
		return nil, fmt.Errorf("Couldn't load config file template")
	}

	var driverConfig XenDriverConfig
	if err := mapstructure.WeakDecode(task.Config, &driverConfig); err != nil {
		return nil, err
	}

	baseImagePath := driverConfig.BaseImagePath
	if baseImagePath == "" {
		return nil, fmt.Errorf("Base image path must be specified.")
	}

	imagePath, err := d.qcowImageFromBase(ctx, task, baseImagePath, ctx.AllocID)
	if imagePath == "" || err != nil {
		return nil, err
	}

	disks := []string{
		imagePath,
	}

	// TODO this assumes the allocation ID is random enough to use as
	// a MAC address basis
	hexAllocId := strings.Replace(ctx.AllocID, "-", "", -1)
	macAddress := strings.ToLower(fmt.Sprintf(
		"%s:%s:%s:%s", xenMacPrefix, hexAllocId[0:2], hexAllocId[2:4], hexAllocId[4:6]))

	domainName := fmt.Sprintf("nomad-%s", ctx.AllocID)
	domainConfig := xenDomainConfig{
		Name:       domainName,
		CPUCount:   1, // TODO use the resources
		Memory:     task.Resources.MemoryMB,
		MACAddress: macAddress,
		Disks:      disks,
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

	// set instance ID in consul
	kv := getKVClient()
	kvPair := &api.KVPair{
		Key:   fmt.Sprintf("%s/meta-data/instance-id", macAddress),
		Value: []byte(ctx.AllocID),
	}
	kv.Put(kvPair, nil)

	h := &xenHandle{
		consulPrefix: fmt.Sprintf("%s/", macAddress),
		domainName:   domainName,
		logger:       d.logger,
		doneCh:       make(chan struct{}),
		waitCh:       make(chan *cstructs.WaitResult, 1),
	}

	xlCmd := exec.Command("xl", "create", cfgFilePath)
	if err := xlCmd.Run(); err != nil {
		return nil, err
	}

	go h.run()
	return h, nil
}

func (h *xenHandle) ID() string {
	return h.domainName
}

func (h *xenHandle) WaitCh() chan *cstructs.WaitResult {
	return h.waitCh
}

func (h *xenHandle) Update(task *structs.Task) error {
	// Update is not possible
	return nil
}

func (h *xenHandle) Kill() error {
	killCmd := exec.Command("xl", "destroy", h.domainName)
	killCmd.Run()

	// clear instance ID in consul. maybe worth leaving this around? idk,
	// i doubt it
	kv := getKVClient()
	kv.DeleteTree(h.consulPrefix, nil)

	return nil
}

// TODO this is super hacky but i really don't want to deal with parsing
// xenstore into a tree structure right now for POC sake
func (h *xenHandle) isDomainActive() bool {
	// TODO move this to using libxenlight or xenbus or something as
	// opposed to parsing command output
	outBytes, err := exec.Command("xenstore-ls", "/local/domain", "-f").Output()
	if err != nil {
		// gross but better than exploding
		return true
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
