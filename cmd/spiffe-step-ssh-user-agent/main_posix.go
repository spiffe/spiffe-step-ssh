//go:build !windows
package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh/agent"
)

func setupAgentInteraction(allowInternal bool) (agent.ExtendedAgent, bool) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock != "" {
		conn, err := net.Dial("unix", sock)
		if err == nil {
			return agent.NewClient(conn).(agent.ExtendedAgent), false
		}
	}

	if allowInternal {
		tempDir, err := os.MkdirTemp("", "spiffe-step-agent.*")
		if err != nil {
			return nil, false
		}
		path := filepath.Join(tempDir, "agent.sock")
		l, err := net.Listen("unix", path)
		if err != nil {
			os.RemoveAll(tempDir)
			return nil, false
		}
		fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", path)
		fmt.Printf("SSH_AGENT_PID=%d; export SSH_AGENT_PID;\n", os.Getpid())
		fmt.Printf("echo Agent pid %d;\n", os.Getpid())
		keyring := agent.NewKeyring().(agent.ExtendedAgent)
		go func() {
			defer l.Close()
			defer os.RemoveAll(tempDir)
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go agent.ServeAgent(keyring, conn)
			}
		}()
		return keyring, true
	}

	return nil, false
}
