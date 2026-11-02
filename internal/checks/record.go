package checks

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
	"time"

	"github.com/rviscuso/warden/internal/hardening"
	"github.com/rviscuso/warden/internal/state"
	"github.com/rviscuso/warden/internal/wardenbin"
)

const idRecorded = "canary.recorded"

// canaryRecorded is up's stand-in for the canary, which is too slow for
// every up: init or check must have recorded a canary pass on this daemon,
// with this binary and these hardening settings. Otherwise up never starts
// containers whose hardening hasn't been proven.
func (r *run) canaryRecorded() {
	const title = "Canary passed for this daemon, binary and settings"
	const fix = "run warden check"
	if !r.need(idRecorded, title, "config.valid", "daemon.pin") {
		return
	}
	st, err := state.Load(r.env.Dirs.StateFile())
	if errors.Is(err, fs.ErrNotExist) {
		r.fail(idRecorded, title, "no pinned daemon", "run warden init")
		return
	}
	if err != nil {
		r.fail(idRecorded, title, oneLine(err), "")
		return
	}
	rec := st.CanaryPass
	if rec == nil {
		r.fail(idRecorded, title, "no canary pass recorded (or the last canary run failed)", fix)
		return
	}
	cur, err := r.currentProof()
	if err != nil {
		r.fail(idRecorded, title, oneLine(err), errFix(err))
		return
	}
	var diffs []string
	if rec.DaemonID != cur.DaemonID {
		diffs = append(diffs, fmt.Sprintf("daemon %s, recorded %s", cur.DaemonID, rec.DaemonID))
	}
	if rec.BinarySHA256 != cur.BinarySHA256 {
		diffs = append(diffs, fmt.Sprintf("warden binary %s, recorded %s", short(cur.BinarySHA256), short(rec.BinarySHA256)))
	}
	if rec.HardeningSHA256 != cur.HardeningSHA256 {
		diffs = append(diffs, fmt.Sprintf("hardening settings %s, recorded %s", short(cur.HardeningSHA256), short(rec.HardeningSHA256)))
	}
	if len(diffs) > 0 {
		r.fail(idRecorded, title, "the canary pass doesn't match: "+strings.Join(diffs, "; "), fix)
		return
	}
	r.pass(idRecorded, title, "canary passed "+rec.At.UTC().Format(time.RFC3339)+" on this daemon, with this binary and these settings")
}

// currentProof is what a canary pass would record now: the pinned
// daemon, the verified binary copy's hash, the hardening digest.
func (r *run) currentProof() (state.CanaryPass, error) {
	exe := r.env.Canary.Executable
	if exe == nil {
		return state.CanaryPass{}, errors.New("no way to find the running warden binary")
	}
	path, err := exe()
	if err != nil {
		return state.CanaryPass{}, fmt.Errorf("finding the warden binary: %w", err)
	}
	bin, err := wardenbin.Find(path, r.env.Dirs.BinDir(), r.env.UID, r.env.GOARCH)
	if err != nil {
		return state.CanaryPass{}, err
	}
	mptcp, err := hardening.HostMPTCP(r.env.Root)
	if err != nil {
		return state.CanaryPass{}, err
	}
	res := r.rep.Config.Controller.Resources
	digest, err := hardening.Digest(r.env.UID, r.env.GID,
		hardening.Resources{MemoryMB: res.MemoryMB, CPUs: res.CPUs, Pids: res.PIDs}, hardening.Host{MPTCP: mptcp})
	if err != nil {
		return state.CanaryPass{}, err
	}
	return state.CanaryPass{
		DaemonID: r.rep.Daemon.ID, BinarySHA256: strings.TrimPrefix(filepath.Base(bin), "warden-"), HardeningSHA256: digest,
	}, nil
}
