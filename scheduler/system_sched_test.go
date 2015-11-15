package scheduler

import (
	"testing"
	"time"

	"github.com/hashicorp/nomad/nomad/mock"
	"github.com/hashicorp/nomad/nomad/structs"
)

func TestSystemSched_JobRegister(t *testing.T) {
	h := NewHarness(t)

	// Create some nodes
	for i := 0; i < 10; i++ {
		node := mock.Node()
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Create a job
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	// Create a mock evaluation to deregister the job
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    job.Priority,
		TriggeredBy: structs.EvalTriggerJobRegister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan allocated
	var planned []*structs.Allocation
	for _, allocList := range plan.NodeAllocation {
		planned = append(planned, allocList...)
	}
	if len(planned) != 10 {
		t.Fatalf("bad: %#v", plan)
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure all allocations placed
	if len(out) != 10 {
		t.Fatalf("bad: %#v", out)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)
}

func TestSystemSched_JobRegister_AddNode(t *testing.T) {
	h := NewHarness(t)

	// Create some nodes
	var nodes []*structs.Node
	for i := 0; i < 10; i++ {
		node := mock.Node()
		nodes = append(nodes, node)
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Generate a fake job with allocations
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	var allocs []*structs.Allocation
	for _, node := range nodes {
		alloc := mock.Alloc()
		alloc.Job = job
		alloc.JobID = job.ID
		alloc.NodeID = node.ID
		alloc.Name = "my-job.web[0]"
		allocs = append(allocs, alloc)
	}
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), allocs))

	// Add a new node.
	node := mock.Node()
	noErr(t, h.State.UpsertNode(h.NextIndex(), node))

	// Create a mock evaluation to deal with the node update
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    50,
		TriggeredBy: structs.EvalTriggerNodeUpdate,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan had no node updates
	var update []*structs.Allocation
	for _, updateList := range plan.NodeUpdate {
		update = append(update, updateList...)
	}
	if len(update) != 0 {
		t.Log(len(update))
		t.Fatalf("bad: %#v", plan)
	}

	// Ensure the plan allocated on the new node
	var planned []*structs.Allocation
	for _, allocList := range plan.NodeAllocation {
		planned = append(planned, allocList...)
	}
	if len(planned) != 1 {
		t.Fatalf("bad: %#v", plan)
	}

	// Ensure it allocated on the right node
	if _, ok := plan.NodeAllocation[node.ID]; !ok {
		t.Fatalf("allocated on wrong node: %#v", plan)
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure all allocations placed
	out = structs.FilterTerminalAllocs(out)
	if len(out) != 11 {
		t.Fatalf("bad: %#v", out)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)
}

func TestSystemSched_JobRegister_AllocFail(t *testing.T) {
	h := NewHarness(t)

	// Create NO nodes
	// Create a job
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	// Create a mock evaluation to register the job
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    job.Priority,
		TriggeredBy: structs.EvalTriggerJobRegister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure no plan as this should be a no-op.
	if len(h.Plans) != 0 {
		t.Fatalf("bad: %#v", h.Plans)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)
}

func TestSystemSched_JobModify(t *testing.T) {
	h := NewHarness(t)

	// Create some nodes
	var nodes []*structs.Node
	for i := 0; i < 10; i++ {
		node := mock.Node()
		nodes = append(nodes, node)
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Generate a fake job with allocations
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	var allocs []*structs.Allocation
	for _, node := range nodes {
		alloc := mock.Alloc()
		alloc.Job = job
		alloc.JobID = job.ID
		alloc.NodeID = node.ID
		alloc.Name = "my-job.web[0]"
		allocs = append(allocs, alloc)
	}
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), allocs))

	// Add a few terminal status allocations, these should be ignored
	var terminal []*structs.Allocation
	for i := 0; i < 5; i++ {
		alloc := mock.Alloc()
		alloc.Job = job
		alloc.JobID = job.ID
		alloc.NodeID = nodes[i].ID
		alloc.Name = "my-job.web[0]"
		alloc.DesiredStatus = structs.AllocDesiredStatusFailed
		terminal = append(terminal, alloc)
	}
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), terminal))

	// Update the job
	job2 := mock.SystemJob()
	job2.ID = job.ID

	// Update the task, such that it cannot be done in-place
	job2.TaskGroups[0].Tasks[0].Config["command"] = "/bin/other"
	noErr(t, h.State.UpsertJob(h.NextIndex(), job2))

	// Create a mock evaluation to deal with drain
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    50,
		TriggeredBy: structs.EvalTriggerJobRegister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan evicted all allocs
	var update []*structs.Allocation
	for _, updateList := range plan.NodeUpdate {
		update = append(update, updateList...)
	}
	if len(update) != len(allocs) {
		t.Fatalf("bad: %#v", plan)
	}

	// Ensure the plan allocated
	var planned []*structs.Allocation
	for _, allocList := range plan.NodeAllocation {
		planned = append(planned, allocList...)
	}
	if len(planned) != 10 {
		t.Fatalf("bad: %#v", plan)
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure all allocations placed
	out = structs.FilterTerminalAllocs(out)
	if len(out) != 10 {
		t.Fatalf("bad: %#v", out)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)
}

func TestSystemSched_JobModify_Rolling(t *testing.T) {
	h := NewHarness(t)

	// Create some nodes
	var nodes []*structs.Node
	for i := 0; i < 10; i++ {
		node := mock.Node()
		nodes = append(nodes, node)
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Generate a fake job with allocations
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	var allocs []*structs.Allocation
	for _, node := range nodes {
		alloc := mock.Alloc()
		alloc.Job = job
		alloc.JobID = job.ID
		alloc.NodeID = node.ID
		alloc.Name = "my-job.web[0]"
		allocs = append(allocs, alloc)
	}
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), allocs))

	// Update the job
	job2 := mock.SystemJob()
	job2.ID = job.ID
	job2.Update = structs.UpdateStrategy{
		Stagger:     30 * time.Second,
		MaxParallel: 5,
	}

	// Update the task, such that it cannot be done in-place
	job2.TaskGroups[0].Tasks[0].Config["command"] = "/bin/other"
	noErr(t, h.State.UpsertJob(h.NextIndex(), job2))

	// Create a mock evaluation to deal with drain
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    50,
		TriggeredBy: structs.EvalTriggerJobRegister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan evicted only MaxParallel
	var update []*structs.Allocation
	for _, updateList := range plan.NodeUpdate {
		update = append(update, updateList...)
	}
	if len(update) != job2.Update.MaxParallel {
		t.Fatalf("bad: %#v", plan)
	}

	// Ensure the plan allocated
	var planned []*structs.Allocation
	for _, allocList := range plan.NodeAllocation {
		planned = append(planned, allocList...)
	}
	if len(planned) != job2.Update.MaxParallel {
		t.Fatalf("bad: %#v", plan)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)

	// Ensure a follow up eval was created
	eval = h.Evals[0]
	if eval.NextEval == "" {
		t.Fatalf("missing next eval")
	}

	// Check for create
	if len(h.CreateEvals) == 0 {
		t.Fatalf("missing created eval")
	}
	create := h.CreateEvals[0]
	if eval.NextEval != create.ID {
		t.Fatalf("ID mismatch")
	}
	if create.PreviousEval != eval.ID {
		t.Fatalf("missing previous eval")
	}

	if create.TriggeredBy != structs.EvalTriggerRollingUpdate {
		t.Fatalf("bad: %#v", create)
	}
}

func TestSystemSched_JobModify_InPlace(t *testing.T) {
	h := NewHarness(t)

	// Create some nodes
	var nodes []*structs.Node
	for i := 0; i < 10; i++ {
		node := mock.Node()
		nodes = append(nodes, node)
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Generate a fake job with allocations
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	var allocs []*structs.Allocation
	for _, node := range nodes {
		alloc := mock.Alloc()
		alloc.Job = job
		alloc.JobID = job.ID
		alloc.NodeID = node.ID
		alloc.Name = "my-job.web[0]"
		allocs = append(allocs, alloc)
	}
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), allocs))

	// Update the job
	job2 := mock.SystemJob()
	job2.ID = job.ID
	noErr(t, h.State.UpsertJob(h.NextIndex(), job2))

	// Create a mock evaluation to deal with drain
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    50,
		TriggeredBy: structs.EvalTriggerJobRegister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan did not evict any allocs
	var update []*structs.Allocation
	for _, updateList := range plan.NodeUpdate {
		update = append(update, updateList...)
	}
	if len(update) != 0 {
		t.Fatalf("bad: %#v", plan)
	}

	// Ensure the plan updated the existing allocs
	var planned []*structs.Allocation
	for _, allocList := range plan.NodeAllocation {
		planned = append(planned, allocList...)
	}
	if len(planned) != 10 {
		t.Fatalf("bad: %#v", plan)
	}
	for _, p := range planned {
		if p.Job != job2 {
			t.Fatalf("should update job")
		}
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure all allocations placed
	if len(out) != 10 {
		t.Fatalf("bad: %#v", out)
	}
	h.AssertEvalStatus(t, structs.EvalStatusComplete)

	// Verify the network did not change
	rp := structs.Port{"main", 5000}
	for _, alloc := range out {
		for _, resources := range alloc.TaskResources {
			if resources.Networks[0].ReservedPorts[0] != rp {
				t.Fatalf("bad: %#v", alloc)
			}
		}
	}
}

func TestSystemSched_JobDeregister(t *testing.T) {
	h := NewHarness(t)

	// Create some nodes
	var nodes []*structs.Node
	for i := 0; i < 10; i++ {
		node := mock.Node()
		nodes = append(nodes, node)
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Generate a fake job with allocations
	job := mock.SystemJob()

	var allocs []*structs.Allocation
	for _, node := range nodes {
		alloc := mock.Alloc()
		alloc.Job = job
		alloc.JobID = job.ID
		alloc.NodeID = node.ID
		alloc.Name = "my-job.web[0]"
		allocs = append(allocs, alloc)
	}
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), allocs))

	// Create a mock evaluation to deregister the job
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    50,
		TriggeredBy: structs.EvalTriggerJobDeregister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan evicted the job from all nodes.
	for _, node := range nodes {
		if len(plan.NodeUpdate[node.ID]) != 1 {
			t.Fatalf("bad: %#v", plan)
		}
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure no remaining allocations
	out = structs.FilterTerminalAllocs(out)
	if len(out) != 0 {
		t.Fatalf("bad: %#v", out)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)
}

func TestSystemSched_NodeDrain(t *testing.T) {
	h := NewHarness(t)

	// Register a draining node
	node := mock.Node()
	node.Drain = true
	noErr(t, h.State.UpsertNode(h.NextIndex(), node))

	// Generate a fake job allocated on that node.
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	alloc := mock.Alloc()
	alloc.Job = job
	alloc.JobID = job.ID
	alloc.NodeID = node.ID
	alloc.Name = "my-job.web[0]"
	noErr(t, h.State.UpsertAllocs(h.NextIndex(), []*structs.Allocation{alloc}))

	// Create a mock evaluation to deal with drain
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    50,
		TriggeredBy: structs.EvalTriggerNodeUpdate,
		JobID:       job.ID,
		NodeID:      node.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure a single plan
	if len(h.Plans) != 1 {
		t.Fatalf("bad: %#v", h.Plans)
	}
	plan := h.Plans[0]

	// Ensure the plan evicted all allocs
	if len(plan.NodeUpdate[node.ID]) != 1 {
		t.Fatalf("bad: %#v", plan)
	}

	// Ensure the plan updated the allocation.
	var planned []*structs.Allocation
	for _, allocList := range plan.NodeUpdate {
		planned = append(planned, allocList...)
	}
	if len(planned) != 1 {
		t.Log(len(planned))
		t.Fatalf("bad: %#v", plan)
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure the allocations is stopped
	if planned[0].DesiredStatus != structs.AllocDesiredStatusStop {
		t.Fatalf("bad: %#v", out)
	}

	h.AssertEvalStatus(t, structs.EvalStatusComplete)
}

func TestSystemSched_RetryLimit(t *testing.T) {
	h := NewHarness(t)
	h.Planner = &RejectPlan{h}

	// Create some nodes
	for i := 0; i < 10; i++ {
		node := mock.Node()
		noErr(t, h.State.UpsertNode(h.NextIndex(), node))
	}

	// Create a job
	job := mock.SystemJob()
	noErr(t, h.State.UpsertJob(h.NextIndex(), job))

	// Create a mock evaluation to deregister the job
	eval := &structs.Evaluation{
		ID:          structs.GenerateUUID(),
		Priority:    job.Priority,
		TriggeredBy: structs.EvalTriggerJobRegister,
		JobID:       job.ID,
	}

	// Process the evaluation
	err := h.Process(NewSystemScheduler, eval)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Ensure multiple plans
	if len(h.Plans) == 0 {
		t.Fatalf("bad: %#v", h.Plans)
	}

	// Lookup the allocations by JobID
	out, err := h.State.AllocsByJob(job.ID)
	noErr(t, err)

	// Ensure no allocations placed
	if len(out) != 0 {
		t.Fatalf("bad: %#v", out)
	}

	// Should hit the retry limit
	h.AssertEvalStatus(t, structs.EvalStatusFailed)
}
