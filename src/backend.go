package main

import (
	"fmt"
	"log"
	"net"
	"time"
)

type BackendRHost struct {
	Enable bool   `json:"enable"`
	Proto  string `json:"proto"`
	RAddr  string `json:"rAddr"`
	RPort  int    `json:"rPort"`
	active bool
}

type Backend struct {
	DetectMethod   string         `json:"detectMethod"`   // "none", "ping", "connect"
	DetectInterval int            `json:"detectInterval"` // "in seconds"
	Mode           string         `json:"mode"`           // "failover", "rr", "wrr"
	RHosts         []BackendRHost `json:"rHosts"`
	rrIdx          int
}

func (be *Backend) Detect() {
	for {
		if be.DetectMethod == "none" {
			// No need todo detection
			log.Println("none detectMethod, ignore", be)
			return
		} else if be.DetectMethod == "ping" {
			// not support
			log.Println("ping detection not support currently")
			return
		} else if be.DetectMethod == "connect" {
			for idx := range be.RHosts {
				host := &be.RHosts[idx]
				if !host.Enable {
					continue
				}
				if host.Proto != "tcp" && host.Proto != "tcp6" {
					log.Println("Warnning: connect detect method only support tcp,tcp6")
					continue
				}
				addr := fmt.Sprintf("%s:%d", host.RAddr, host.RPort)
				conn, err := net.Dial(host.Proto, addr)
				if err != nil {
					// can't connect
					log.Println("Warning: detected host inactive", host)
					host.active = false
				} else {
					conn.Close()
					host.active = true
					// log.Println("detect host active:", host)
				}
			}
		} else {
			log.Println("Unknow detectMethod", be.DetectMethod)
			return
		}
		time.Sleep(time.Duration(be.DetectInterval) * time.Second)
	}
}

func (be *Backend) GetRHost() *BackendRHost {
	if be.RHosts == nil || len(be.RHosts) == 0 {
		log.Println("No rHosts in backend", be)
		return nil
	}

	if be.Mode == "failover" {
		for idx := range be.RHosts {
			host := &be.RHosts[idx]
			if host.Enable && host.active {
				log.Println("[FO] Using rHost", host)
				return host
			}
		}
		return nil
	}

	// TODO: connect from same IP should forward to same rHost
	if be.Mode == "rr" {
		for i := 0; i <= len(be.RHosts); i += 1 {
			idx := (be.rrIdx + i) % len(be.RHosts)
			host := &be.RHosts[idx]
			if !host.Enable || !host.active {
				log.Println("[RR] rHost not enable or active", idx, host)
				continue
			}
			be.rrIdx = (idx + 1)
			log.Println("[RR] Using rHost", be.rrIdx, host)
			return host
		}
		return nil
	}

	return nil
}
