package main

import (
	"errors"
	"strings"

	"github.com/aquasecurity/tracee/types/detect"
	"github.com/aquasecurity/tracee/types/protocol"
	"github.com/aquasecurity/tracee/types/trace"
)

// DangerousCommandExecution detects execution of suspicious commands,
// applying different detection strategies based on whether the event
// originates from a container or the host.
type DangerousCommandExecution struct {
	cb detect.SignatureHandler

	// containerOnlyCommands are suspicious only inside containers
	// (legitimate on host for admin/ops use)
	containerOnlyCommands []string

	// alwaysDangerousPatterns are suspicious regardless of environment
	alwaysDangerousPatterns []dangerousPattern
}

type dangerousPattern struct {
	processName string
	argPatterns []string // any matching arg pattern triggers detection
}

func (sig *DangerousCommandExecution) Init(ctx detect.SignatureContext) error {
	sig.cb = ctx.Callback

	// Recon / enumeration commands: normal on host, suspicious in containers
	sig.containerOnlyCommands = []string{
		"whoami", "id", "hostname", "uname", "nmap", "masscan", "ncat",
	}

	// Reverse shell / dangerous download patterns: always suspicious
	sig.alwaysDangerousPatterns = []dangerousPattern{
		{processName: "nc", argPatterns: []string{"-e"}},
		{processName: "ncat", argPatterns: []string{"-e", "--exec"}},
		{processName: "socat", argPatterns: []string{"exec:"}},
		{processName: "bash", argPatterns: []string{"-i >& /dev/tcp", "-i >&/dev/tcp"}},
		{processName: "wget", argPatterns: []string{"|sh", "|bash", "| sh", "| bash"}},
		{processName: "curl", argPatterns: []string{"|sh", "|bash", "| sh", "| bash"}},
	}

	return nil
}

func (sig *DangerousCommandExecution) GetMetadata() (detect.SignatureMetadata, error) {
	return detect.SignatureMetadata{
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
	}, nil
}

func (sig *DangerousCommandExecution) GetSelectedEvents() ([]detect.SignatureEventSelector, error) {
	return []detect.SignatureEventSelector{
		{Source: "tracee", Name: "sched_process_exec", Origin: "*"},
	}, nil
}

func (sig *DangerousCommandExecution) OnEvent(event protocol.Event) error {
	eventObj, ok := event.Payload.(trace.Event)
	if !ok {
		return errors.New("invalid event")
	}

	switch eventObj.EventName {
	case "sched_process_exec":
		processName := eventObj.ProcessName
		isContainer := eventObj.Container.ID != ""

		argv, err := eventObj.GetSliceStringArgumentByName("argv")
		if err != nil {
			argv = nil
		}

		argsJoined := strings.Join(argv, " ")

		// Check always-dangerous patterns (reverse shell etc.) in all environments
		for _, pattern := range sig.alwaysDangerousPatterns {
			if processName == pattern.processName {
				for _, argPattern := range pattern.argPatterns {
					if strings.Contains(argsJoined, argPattern) {
						return sig.report(event, isContainer)
					}
				}
			}
		}

		// Check container-only commands (recon tools)
		if isContainer {
			for _, cmd := range sig.containerOnlyCommands {
				if processName == cmd {
					return sig.report(event, isContainer)
				}
			}

			// Special case: cat /etc/passwd in container
			if processName == "cat" && strings.Contains(argsJoined, "/etc/passwd") {
				return sig.report(event, isContainer)
			}
		}
	}

	return nil
}

func (sig *DangerousCommandExecution) report(event protocol.Event, isContainer bool) error {
	metadata, err := sig.GetMetadata()
	if err != nil {
		return err
	}

	context := "host"
	if isContainer {
		context = "container"
	}

	sig.cb(&detect.Finding{
		SigMetadata: metadata,
		Event:       event,
		Data: map[string]interface{}{
			"context": context,
		},
	})

	return nil
}

func (sig *DangerousCommandExecution) OnSignal(s detect.Signal) error {
	return nil
}
func (sig *DangerousCommandExecution) Close() {}
