package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type peerRequest struct {
	Note string `json:"note,omitempty"`
}

func main() {
	serverURL := flag.String("server", "http://127.0.0.1:8080", "URL of the WireGuard gateway")
	jwtToken := flag.String("jwt", "", "JWT token used for authentication")
	note := flag.String("note", "", "Optional note sent to the gateway")
	tunnelPath := flag.String("tunnel", "./tunnel.dll", "Path to the tunnel executable")
	debug := flag.Bool("debug", false, "Print the tunnel output")
	flag.Parse()

	if strings.TrimSpace(*jwtToken) == "" {
		fmt.Fprintln(os.Stderr, "--jwt is required")
		os.Exit(2)
	}

	config, err := requestConfig(*serverURL, *jwtToken, *note)
	if err != nil {
		fmt.Fprintf(os.Stderr, "request config: %v\n", err)
		os.Exit(1)
	}

	exitCode, err := runTunnel(*tunnelPath, config, *debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "run tunnel: %v\n", err)
		os.Exit(1)
	}

	os.Exit(exitCode)
}

func requestConfig(serverURL, jwtToken, note string) ([]byte, error) {
	url := strings.TrimRight(serverURL, "/") + "/peer"

	body := peerRequest{}
	if note != "" {
		body.Note = note
	}

	var reqBody io.Reader
	if body.Note != "" {
		buf, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal request: %w", err)
		}
		reqBody = bytes.NewReader(buf)
	}

	req, err := http.NewRequest(http.MethodPost, url, reqBody)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	req.Header.Set("Accept", "application/json")

	dialer := &net.Dialer{}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp4", addr)
		},
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusCreated {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return nil, fmt.Errorf("gateway error: %s", msg)
	}

	return data, nil
}

func runTunnel(tunnelPath string, config []byte, debug bool) (int, error) {
	cmd := exec.Command(tunnelPath, "run", "-c", "stdin")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return 1, fmt.Errorf("stdin pipe: %w", err)
	}

	if debug {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = io.Discard
		cmd.Stderr = io.Discard
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("start tunnel: %w", err)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	forwardDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-forwardDone:
				return
			case sig := <-sigCh:
				if sig != nil {
					_ = cmd.Process.Signal(sig)
				}
			}
		}
	}()

	if _, err := stdin.Write(config); err != nil {
		stdin.Close()
		cmd.Process.Kill()
		cmd.Wait()
		close(forwardDone)
		return 1, fmt.Errorf("write config: %w", err)
	}
	if err := stdin.Close(); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		close(forwardDone)
		return 1, fmt.Errorf("close stdin: %w", err)
	}

	waitErr := cmd.Wait()
	close(forwardDone)

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, fmt.Errorf("wait tunnel: %w", waitErr)
	}

	return 0, nil
}
