package support

import (
	"sync"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// EndWorkProgress is what GET /sessions/{id}/end-work returns so
// enum and the dashboard can see hook work that is not in the backlog
// yet (listing Done IPs, drain wait).
type EndWorkProgress struct {
	Done       bool   `json:"done"`
	Phase      string `json:"phase"`
	Candidates int    `json:"candidates"`
	Requeued   int    `json:"requeued"`
	Waiting    int    `json:"waiting"`
	Leased     int    `json:"leased"`
	Processed  int    `json:"processed"`
}

type endWorkState struct {
	mu         sync.Mutex
	phase      string
	candidates int
	requeued   int
}

var endWorkStates sync.Map // session uuid string -> *endWorkState

func sessionKey(s et.Session) string {
	if s == nil {
		return ""
	}
	return s.ID().String()
}

func stateFor(id string) *endWorkState {
	v, _ := endWorkStates.LoadOrStore(id, &endWorkState{phase: "none"})
	return v.(*endWorkState)
}

func SetEndWorkPhase(s et.Session, phase string) {
	st := stateFor(sessionKey(s))
	st.mu.Lock()
	st.phase = phase
	st.mu.Unlock()
}

func SetEndWorkCandidates(s et.Session, n int) {
	st := stateFor(sessionKey(s))
	st.mu.Lock()
	st.candidates = n
	st.mu.Unlock()
}

func AddEndWorkRequeued(s et.Session, n int) {
	st := stateFor(sessionKey(s))
	st.mu.Lock()
	st.requeued += n
	st.mu.Unlock()
}

func SnapshotEndWork(id uuid.UUID) EndWorkProgress {
	p := EndWorkProgress{Phase: "none"}
	v, ok := endWorkStates.Load(id.String())
	if !ok {
		return p
	}
	st := v.(*endWorkState)
	st.mu.Lock()
	p.Phase = st.phase
	p.Candidates = st.candidates
	p.Requeued = st.requeued
	st.mu.Unlock()
	return p
}
