//go:build windows

package main

import (
	"fmt"
	"net"
	"os"
	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

func setupAgentInteraction(allowInternal bool) (agent.ExtendedAgent, bool) {
	pipePath := `\\.\pipe\openssh-ssh-agent`
	conn, err := winio.DialPipe(pipePath, nil)
	if err == nil {
		return agent.NewClient(conn).(agent.ExtendedAgent), false
	}

	if allowInternal {
		myPipe := `\\.\pipe\spiffe-step-agent`
		l, err := winio.ListenPipe(myPipe, nil)
		if err != nil {
			return nil, false
		}

		fmt.Printf("$env:SSH_AUTH_SOCK='%s'\n", myPipe)
		fmt.Println("# Run the above line to point your SSH client to this agent")

		keyring := agent.NewKeyring().(agent.ExtendedAgent)
		go func() {
			for {
				conn, _ := l.Accept()
				go agent.ServeAgent(keyring, conn)
			}
		}()
		return keyring, true
	}

	return nil, false
}
