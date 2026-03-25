// Package localworker provides an in-process worker that registers with the
// controller and executes jobs using the installed tool modules — no external
// binary or terminal required.
package localworker

import (
	"context"
	"os"
	"sync"
	"time"

	"xpfarm/internal/distributed/controller"
	"xpfarm/internal/modules"
	jobstore "xpfarm/internal/storage/jobs"
	workerstore "xpfarm/internal/storage/workers"
	"xpfarm/pkg/utils"

	"gorm.io/gorm"
)

const LocalWorkerID = "local-worker-1"

// Worker is an in-process worker node.
type Worker struct {
	ctrl   *controller.Controller
	db     *gorm.DB
	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// New creates a LocalWorker bound to the given DB and controller.
func New(db *gorm.DB, ctrl *controller.Controller) *Worker {
	return &Worker{ctrl: ctrl, db: db}
}

// Start registers the worker and begins polling for jobs.
// Returns an error if already running.
func (w *Worker) Start() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.cancel != nil {
		return nil // already running
	}

	// Collect which tools are installed so the controller can route correctly.
	tools := make([]string, 0, 10)
	for _, m := range modules.GetAll() {
		if m.CheckInstalled() {
			tools = append(tools, m.Name())
		}
	}

	hostname, _ := os.Hostname()
	if _, err := w.ctrl.RegisterWorker(LocalWorkerID, hostname, "embedded", tools, []string{"local"}); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	w.cancel = cancel
	w.done = make(chan struct{})

	go w.run(ctx, tools)
	utils.LogInfo("Local worker started — capabilities: %v", tools)
	return nil
}

// Stop gracefully shuts down the local worker.
func (w *Worker) Stop() {
	w.mu.Lock()
	cancel := w.cancel
	done := w.done
	w.cancel = nil
	w.done = nil
	w.mu.Unlock()

	if cancel != nil {
		cancel()
		if done != nil {
			<-done
		}
	}
}

// IsRunning returns true if the worker goroutine is active.
func (w *Worker) IsRunning() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.cancel != nil
}

func (w *Worker) run(ctx context.Context, tools []string) {
	defer close(w.done)

	heartbeat := time.NewTicker(15 * time.Second)
	poll := time.NewTicker(3 * time.Second)
	defer heartbeat.Stop()
	defer poll.Stop()

	for {
		select {
		case <-ctx.Done():
			workerstore.UpdateStatus(w.db, LocalWorkerID, "offline") //nolint:errcheck
			utils.LogInfo("Local worker stopped.")
			return
		case <-heartbeat.C:
			w.ctrl.Heartbeat(LocalWorkerID) //nolint:errcheck
		case <-poll.C:
			job, err := w.ctrl.ClaimNextJob(LocalWorkerID, tools)
			if err != nil || job == nil {
				continue
			}
			go w.executeJob(ctx, job)
		}
	}
}

func (w *Worker) executeJob(ctx context.Context, job *jobstore.JobRecord) {
	payload := jobstore.UnmarshalPayload(job.Payload)
	target, _ := payload["target"].(string)

	mod := modules.Get(job.Tool)
	if mod == nil {
		w.ctrl.RecordJobResult(LocalWorkerID, job.ID, nil, "unknown tool: "+job.Tool) //nolint:errcheck
		return
	}

	jobCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()

	utils.LogInfo("Local worker executing job %s: %s → %s", job.ID, job.Tool, target)
	output, err := mod.Run(jobCtx, target)
	if err != nil {
		w.ctrl.RecordJobResult(LocalWorkerID, job.ID, nil, err.Error()) //nolint:errcheck
		return
	}

	w.ctrl.RecordJobResult(LocalWorkerID, job.ID, map[string]any{"output": output}, "") //nolint:errcheck
}
