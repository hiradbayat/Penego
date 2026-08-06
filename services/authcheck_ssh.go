package services

import (
	"net"
	"strconv"

	"golang.org/x/crypto/ssh"
)

func checkSSHPassword(req AuthCheckRequest) (bool, string) {
	addr := net.JoinHostPort(req.Host, strconv.Itoa(req.Port))
	config := &ssh.ClientConfig{
		User:            req.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(req.Password)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         req.Timeout,
	}
	client, err := ssh.Dial("tcp", addr, config)
	if err != nil {
		return false, "ssh auth failed: " + err.Error()
	}
	_ = client.Close()
	return true, "SSH login accepted"
}
