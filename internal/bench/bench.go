// Package bench holds what wirenet-bench reports and wirenet-lab reads: the JSON
// result of each subcommand, and the latency summary both compute. It uses
// the standard library alone, so wirenet-bench stays a single binary with no
// dependencies to install on a host.
package bench

import (
	"math"
	"slices"
	"time"
)

// Port is where wirenet-bench serves unless told otherwise.
const Port = 5300

// Latency summarizes a set of samples, in milliseconds.
type Latency struct {
	Count int     `json:"count"`
	Mean  float64 `json:"mean_ms"`
	P50   float64 `json:"p50_ms"`
	P90   float64 `json:"p90_ms"`
	P99   float64 `json:"p99_ms"`
	Max   float64 `json:"max_ms"`
}

// Summarize returns the nearest-rank percentiles of samples: the p-th
// percentile is the smallest sample at least p percent of samples do not
// exceed. It sorts samples in place.
func Summarize(samples []time.Duration) Latency {
	if len(samples) == 0 {
		return Latency{}
	}
	slices.Sort(samples)
	var sum time.Duration
	for _, s := range samples {
		sum += s
	}
	ms := func(d time.Duration) float64 { return float64(d) / float64(time.Millisecond) }
	return Latency{
		Count: len(samples),
		Mean:  ms(sum / time.Duration(len(samples))),
		P50:   ms(Percentile(samples, 50)),
		P90:   ms(Percentile(samples, 90)),
		P99:   ms(Percentile(samples, 99)),
		Max:   ms(samples[len(samples)-1]),
	}
}

// Percentile returns the nearest-rank p-th percentile of sorted samples.
func Percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	rank := int(math.Ceil(p / 100 * float64(len(sorted))))
	return sorted[min(max(rank, 1), len(sorted))-1]
}

// Millis converts milliseconds back to a duration, for summarizing values
// that arrived in a report.
func Millis(ms float64) time.Duration { return time.Duration(ms * float64(time.Millisecond)) }

// Stream is a throughput run over parallel connections.
type Stream struct {
	Target   string `json:"target"`
	Reverse  bool   `json:"reverse"`
	Parallel int    `json:"parallel"`
	// Seconds runs from the first byte sent to the last byte acknowledged
	// by the server, so data still in flight at the deadline counts.
	Seconds       float64      `json:"seconds"`
	Bytes         int64        `json:"bytes"`
	BitsPerSecond float64      `json:"bits_per_second"`
	Retransmits   uint64       `json:"retransmits"`
	Conns         []StreamConn `json:"conns"`
}

// StreamConn is one connection of a stream run.
type StreamConn struct {
	Bytes int64 `json:"bytes"`
	// Retransmits and RTT come from the sender's TCP_INFO, so they are
	// reported only when the client sends.
	Retransmits uint32  `json:"retransmits"`
	RTT         float64 `json:"rtt_ms"`
}

// RR is a request/response run over one connection.
type RR struct {
	Target  string  `json:"target"`
	Size    int     `json:"size"`
	Connect float64 `json:"connect_ms"`
	Latency Latency `json:"latency"`
	// WorstAt is when the slowest round trip began, in Unix nanoseconds.
	WorstAt int64  `json:"worst_at_unix_ns"`
	Start   int64  `json:"start_unix_ns"`
	End     int64  `json:"end_unix_ns"`
	Error   string `json:"error,omitempty"`
}

// CPU is the host-wide CPU time spent during a window, from /proc/stat, in
// CPU-seconds.
type CPU struct {
	Seconds float64 `json:"seconds"`
	CPUs    int     `json:"cpus"`
	Busy    float64 `json:"busy_s"`
	User    float64 `json:"user_s"`
	System  float64 `json:"system_s"`
	IRQ     float64 `json:"irq_s"`
	SoftIRQ float64 `json:"softirq_s"`
	Steal   float64 `json:"steal_s"`
	Idle    float64 `json:"idle_s"`
}

// Dials is the result of dial loops, one per namespace.
type Dials struct {
	Results []Dial `json:"results"`
}

// Dial is one namespace's dial loop: connect, read the server's name, and
// repeat until the answer has been the wanted one Streak times running.
type Dial struct {
	Namespace string `json:"namespace"`
	Target    string `json:"target"`
	Want      string `json:"want,omitempty"`
	// Refused counts a failed connection as the wanted outcome.
	Refused bool  `json:"refused,omitempty"`
	Reached bool  `json:"reached"`
	Start   int64 `json:"start_unix_ns"`
	// Times are attempts' launches, except FirstDone. First is the first
	// wanted answer, and FirstDone when the earliest one completed.
	// Converged begins the final run of wanted answers, and Other is the
	// last attempt before it that another server answered.
	First     int64          `json:"first_unix_ns"`
	FirstDone int64          `json:"first_done_unix_ns"`
	Converged int64          `json:"converged_unix_ns"`
	Other     int64          `json:"other_unix_ns"`
	Attempts  int            `json:"attempts"`
	Failures  int            `json:"failures"`
	Answers   map[string]int `json:"answers"`
	Error     string         `json:"error,omitempty"`
	// Missed holds the last attempts launched before Converged that got
	// another outcome, the latest last, so a late settle shows what held
	// it up.
	Missed []Missed `json:"missed,omitempty"`
}

// Lookup is one namespace's lookup loop: ask its resolver for a name until
// the answer holds the wanted address, or holds addresses and not Unlike.
type Lookup struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Want      string `json:"want,omitempty"`
	Unlike    string `json:"unlike,omitempty"`
	Found     bool   `json:"found"`
	Start     int64  `json:"start_unix_ns"`
	// First is when the first attempt with the answer sought launched, and
	// Got is that answer.
	First    int64    `json:"first_unix_ns"`
	Got      []string `json:"got,omitempty"`
	Attempts int      `json:"attempts"`
	// Last is the answer, or the error, of the last attempt before it.
	Last  string `json:"last,omitempty"`
	Error string `json:"error,omitempty"`
}

// Missed is one attempt that got an outcome its loop was not waiting for.
type Missed struct {
	Launched int64   `json:"launched_unix_ns"`
	MS       float64 `json:"ms"`
	Outcome  string  `json:"outcome"`
}

// MissedKept is how many missed attempts a Dial keeps.
const MissedKept = 8

// Elapsed is the time from the loop's start to convergence.
func (d Dial) Elapsed() time.Duration { return time.Duration(d.Converged - d.Start) }

// API is a run of admin calls with one token. Each round reads a network,
// then creates a rule in it and deletes it again, each call timed alone.
type API struct {
	Read   Latency `json:"read"`
	Create Latency `json:"create"`
	Delete Latency `json:"delete"`
	// Writes counts the creates and deletes sent, Limited those refused
	// with 429, and Failures every other answer but 200.
	Writes   int `json:"writes"`
	Limited  int `json:"limited"`
	Failures int `json:"failures"`
	// Hidden is the status a second network answered.
	Hidden  int     `json:"hidden,omitempty"`
	Seconds float64 `json:"seconds"`
	// Samples holds every successful call's time in milliseconds, by
	// call, so runs pool exactly.
	Samples map[string][]float64 `json:"samples"`
	// Answered holds when each write that succeeded was answered, in
	// seconds from the run's start.
	Answered []float64 `json:"answered"`
}

// Attach is a run of attach-to-first-connection rounds.
type Attach struct {
	Rounds    []AttachRound `json:"rounds"`
	Attach    Latency       `json:"attach"`
	FirstConn Latency       `json:"first_conn"`
	Reached   int           `json:"reached"`
	Failures  int           `json:"failures"`
}

// AttachRound is one attach: the local API's answer, then the first
// connection from the new namespace, both timed from the attach request.
type AttachRound struct {
	Interface string  `json:"interface"`
	Namespace string  `json:"namespace"`
	Addr6     string  `json:"addr6"`
	AttachMS  float64 `json:"attach_ms"`
	FirstConn float64 `json:"first_conn_ms"`
	Reached   bool    `json:"reached"`
	Error     string  `json:"error,omitempty"`
}

// Detach is one timed detach.
type Detach struct {
	Interface string  `json:"interface"`
	Start     int64   `json:"start_unix_ns"`
	Done      int64   `json:"done_unix_ns"`
	MS        float64 `json:"ms"`
}

// Churn is sustained attach-and-detach against one agent.
type Churn struct {
	Seconds     float64  `json:"seconds"`
	Concurrency int      `json:"concurrency"`
	Attempts    int      `json:"attempts"`
	Attached    int      `json:"attached"`
	Detached    int      `json:"detached"`
	Failures    int      `json:"failures"`
	Errors      []string `json:"errors,omitempty"`
	// PerSecond counts completed attach-and-detach pairs.
	PerSecond float64 `json:"per_second"`
	Attach    Latency `json:"attach"`
	Detach    Latency `json:"detach"`
}

// Density attaches interfaces to one agent until an attach fails, attach
// latency degrades, or the cap is reached, then detaches them all.
type Density struct {
	Max        int       `json:"max"`
	Interfaces int       `json:"interfaces"`
	Stopped    string    `json:"stopped"`
	Error      string    `json:"error,omitempty"`
	AttachMS   []float64 `json:"attach_ms"`
	First      Latency   `json:"first_window"`
	Last       Latency   `json:"last_window"`
	Verified   int       `json:"verified"`
	Reached    int       `json:"reached"`
	Detached   int       `json:"detached"`
	// DetachFailures counts interfaces left attached.
	DetachFailures int     `json:"detach_failures"`
	Detach         Latency `json:"detach"`
	DetachSeconds  float64 `json:"detach_seconds"`
	// MemAvailable is the host's, in kibibytes, before the first attach
	// and with every interface attached.
	MemBefore int64 `json:"mem_available_before_kib"`
	MemPeak   int64 `json:"mem_available_peak_kib"`
}
