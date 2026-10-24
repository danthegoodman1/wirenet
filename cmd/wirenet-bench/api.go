//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/danthegoodman1/wirenet/internal/bench"
)

// api times admin calls with one token: each round reads a network, then
// creates a rule between two of its services on a port of its own and
// deletes it. It speaks HTTP itself, so a 429 counts as an answer rather
// than a wait.
func api(args []string) error {
	fs := flag.NewFlagSet("api", flag.ContinueOnError)
	cp := fs.String("cp", "", "the control plane's URL")
	token := fs.String("token", "", "the bearer token")
	tokenFile := fs.String("token-file", "", "a file holding the bearer token")
	network := fs.String("network", "", "the network to read and write rules in")
	hidden := fs.String("hidden", "", "a second network to read once, recording its status")
	from := fs.String("from", "new", "the rules' source service")
	to := fs.String("to", "peer", "the rules' destination service")
	rounds := fs.Int("rounds", 20, "rounds of a read, a create and a delete")
	duration := fs.Duration("duration", 0, "run rounds back to back for this long, in place of --rounds")
	base := fs.Int("port", 20000, "the first round's rule port; each round takes the next")
	if err := parse(fs, args); err != nil {
		return err
	}
	if *tokenFile != "" {
		b, err := os.ReadFile(*tokenFile)
		if err != nil {
			return err
		}
		*token = strings.TrimSpace(string(b))
	}
	if *cp == "" || *token == "" || *network == "" {
		return errors.New("api: --cp, a token and --network are required")
	}
	if *base < 1 || *base > 65535 {
		return errors.New("api: --port must name a port")
	}
	c := &adminClient{base: strings.TrimRight(*cp, "/"), token: *token, http: &http.Client{Timeout: 30 * time.Second}}
	var out bench.API
	var reads, creates, deletes []time.Duration
	net := "/v1/networks/" + url.PathEscape(*network)
	start := time.Now()
	answered := func() { out.Answered = append(out.Answered, time.Since(start).Seconds()) }
	// Rules a refused delete left behind, removed once the timing ends.
	var left []string
	for i := 0; *duration > 0 && time.Since(start) < *duration || *duration == 0 && i < *rounds; i++ {
		t := time.Now()
		status, _, err := c.call("GET", net, nil)
		if err != nil {
			return err
		}
		if c.counted(&out, status) {
			reads = append(reads, time.Since(t))
		}
		port := *base + i%(65536-*base)
		rule := map[string]any{"from": *from, "to": *to, "proto": "tcp", "ports": map[string]int{"lo": port, "hi": port}}
		t = time.Now()
		status, body, err := c.call("POST", net+"/rules", rule)
		if err != nil {
			return err
		}
		out.Writes++
		if !c.counted(&out, status) {
			continue
		}
		creates = append(creates, time.Since(t))
		answered()
		var created struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &created); err != nil || created.ID == "" {
			return fmt.Errorf("api: rule create answered %q", body)
		}
		t = time.Now()
		status, _, err = c.call("DELETE", net+"/rules/"+url.PathEscape(created.ID), nil)
		if err != nil {
			return err
		}
		out.Writes++
		if c.counted(&out, status) {
			deletes = append(deletes, time.Since(t))
			answered()
		} else {
			left = append(left, created.ID)
		}
	}
	out.Seconds = time.Since(start).Seconds()
	if err := c.remove(net, left); err != nil {
		return err
	}
	if *hidden != "" {
		status, _, err := c.call("GET", "/v1/networks/"+url.PathEscape(*hidden), nil)
		if err != nil {
			return err
		}
		out.Hidden = status
	}
	out.Read, out.Create, out.Delete = bench.Summarize(reads), bench.Summarize(creates), bench.Summarize(deletes)
	out.Samples = map[string][]float64{"read": millis(reads), "create": millis(creates), "delete": millis(deletes)}
	return emit(out)
}

type adminClient struct {
	base, token string
	http        *http.Client
}

func (c *adminClient) call(method, path string, in any) (int, []byte, error) {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return 0, nil, err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return resp.StatusCode, b, err
}

// counted tallies a status, and reports whether the call succeeded.
func (c *adminClient) counted(out *bench.API, status int) bool {
	switch status {
	case http.StatusOK:
		return true
	case http.StatusTooManyRequests:
		out.Limited++
	default:
		out.Failures++
	}
	return false
}

func millis(ds []time.Duration) []float64 {
	out := make([]float64, len(ds))
	for i, d := range ds {
		out[i] = float64(d) / float64(time.Millisecond)
	}
	return out
}

// remove deletes rules, waiting out each limited answer, so a run leaves
// the network as it found it.
func (c *adminClient) remove(net string, ids []string) error {
	deadline := time.Now().Add(5 * time.Minute)
	for _, id := range ids {
		for {
			status, body, err := c.call("DELETE", net+"/rules/"+url.PathEscape(id), nil)
			switch {
			case err != nil:
				return err
			case status == http.StatusOK || status == http.StatusNotFound:
			case status == http.StatusTooManyRequests && time.Now().Before(deadline):
				time.Sleep(time.Second)
				continue
			default:
				return fmt.Errorf("api: removing rule %s: %d %s", id, status, body)
			}
			break
		}
	}
	return nil
}
