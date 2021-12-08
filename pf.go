package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

type FwdRule struct {
	Proto     string `json:"proto"`
	LAddr     string `json:"lAddr"`
	LPort     int    `json:"lPort"`
	RAddr     string `json:"rAddr"`
	RPort     int    `json:"rPort"`
	IpSetName string `json:"ipset"`
	IpNets    *[]*net.IPNet
}

func (r *FwdRule) CheckIp(ip net.IP) bool {
	if r.IpNets == nil {
		return true
	}
	// if len(*r.IpNets) == 0 {
	// 	log.Println("IPset is empty, always match.")
	// 	return true
	// }
	for i := range *r.IpNets {
		net := (*r.IpNets)[i]
		// log.Println("CheckIP", ip, net)
		if net.Contains(ip) {
			// log.Println("IP Check OK")
			return true
		}
	}
	return false
}

type Config struct {
	Rules    []FwdRule           `json:"rules"`
	IpSetMap map[string][]string `json:"ipsets"`
	IpNets   map[string][]*net.IPNet
}

func (c *Config) LoadJson(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Println(err)
		return
	}
	err = json.Unmarshal(data, c)
	if err != nil {
		log.Println(err)
		return
	}
	c.IpNets = make(map[string][]*net.IPNet)
	for n, v := range c.IpSetMap {
		log.Println("Processing IpSet", n, v)
		nets := make([]*net.IPNet, len(v))
		for i := range v {
			log.Println("processing", n, v[i])
			_, ipnet, err := net.ParseCIDR(v[i])
			if err != nil {
				log.Println(err)
				continue
			}
			nets[i] = ipnet
		}
		c.IpNets[n] = nets
	}
	for i := range c.Rules {
		ipnets, exists := c.IpNets[c.Rules[i].IpSetName]
		if exists {
			c.Rules[i].IpNets = &ipnets
		}
	}
	log.Println("Load config OK")
}

type TCPFwdEntry struct {
	rule  FwdRule
	connL net.Conn
	connR net.Conn
}

func (e *TCPFwdEntry) L2R() {
	buf := make([]byte, 2048)
	for {
		n, err := e.connL.Read(buf)
		if err != nil {
			log.Println(err)
			e.connR.Close()
			return
		}
		_, err = e.connR.Write(buf[:n])
		if err != nil {
			log.Println(err)
			e.connR.Close()
			return
		}
	}
}

func (e *TCPFwdEntry) R2L() {
	buf := make([]byte, 2048)
	for {
		n, err := e.connR.Read(buf)
		if err != nil {
			log.Println(err)
			e.connL.Close()
			return
		}
		_, err = e.connL.Write(buf[:n])
		if err != nil {
			log.Println(err)
			e.connL.Close()
			return
		}
	}
}

func (e *TCPFwdEntry) Run() {
	addr := fmt.Sprintf("%s:%d", e.rule.RAddr, e.rule.RPort)
	connR, err := net.Dial(e.rule.Proto, addr)
	if err != nil {
		log.Println("Dial remote failed", err)
		return
	}
	e.connR = connR
	go e.L2R()
	e.R2L()
}

func RunFwdRuleTCP(rule FwdRule) {
	port := rule.LPort
	addr := net.TCPAddr{Port: int(port)}
	log.Println("listen TCP", addr)
	ln, err := net.ListenTCP(rule.Proto, &addr)
	if err != nil {
		log.Println(err)
		return
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println(err)
			return
		}
		log.Println("Accept from", conn.RemoteAddr())
		rIpStr := conn.RemoteAddr().String()
		rIpStr = rIpStr[:strings.LastIndex(rIpStr, ":")]
		rIpStr = strings.Trim(rIpStr, "[]")
		// log.Println("rIpStr:", rIpStr)
		ip := net.ParseIP(rIpStr)
		// log.Println("ip:", ip)
		if !rule.CheckIp(ip) {
			log.Println("Remote not in set, ignore.")
			conn.Close()
			continue
		}
		entry := TCPFwdEntry{
			rule:  rule,
			connL: conn,
		}
		go entry.Run()
	}
}

type UDPFwdEntry struct {
	rule    FwdRule
	connL   *net.UDPConn
	connR   net.Conn
	lAddr   *net.UDPAddr
	lastAct time.Time
	// remoteAddr net.Addr
}

func (e *UDPFwdEntry) L2R(buf []byte, len int) {
	e.connR.Write(buf[:len])
	e.lastAct = time.Now()
}

func (e *UDPFwdEntry) R2L() {
	buf := make([]byte, 65535)
	for {
		n, err := e.connR.Read(buf)
		if err != nil {
			log.Println(err)
			return
		}
		_, err = e.connL.WriteToUDP(buf[:n], e.lAddr)
		if err != nil {
			log.Println(err)
			return
		}
		e.lastAct = time.Now()
	}
}

func RunFwdRuleUDP(rule FwdRule) {
	port := rule.LPort
	addr := net.UDPAddr{Port: int(port)}
	log.Println("listen UDP", addr)
	connL, err := net.ListenUDP(rule.Proto, &addr)
	if err != nil {
		log.Println(err)
		return
	}
	buf := make([]byte, 65535)
	fwdMap := make(map[string]*UDPFwdEntry)
	for {
		n, addr, err := connL.ReadFromUDP(buf)
		if err != nil {
			log.Println(n, err)
			return
		}
		addrstr := addr.String()
		e, exists := fwdMap[addrstr]
		if exists {
			e.L2R(buf, n)
		} else {
			log.Println("UDP new conn from:", addrstr)
			if !rule.CheckIp(addr.IP) {
				log.Println("UDP addr not in set, ignore. remote:", addr.String())
				continue
			}
			connR, err := net.Dial(rule.Proto, fmt.Sprintf("%s:%d", rule.RAddr, rule.RPort))
			if err != nil {
				log.Println(err)
				continue
			}
			entry := UDPFwdEntry{
				rule:    rule,
				connL:   connL,
				connR:   connR,
				lAddr:   addr,
				lastAct: time.Now(),
			}
			fwdMap[addrstr] = &entry
			go entry.R2L()
			// clean up timeout sessions
			for idx := range fwdMap {
				e := fwdMap[idx]
				now := time.Now()
				if now.After(e.lastAct.Add(15 * time.Second)) {
					// log.Println("timeout", e.lastAct, now)
					e.connR.Close()
					delete(fwdMap, idx)
				}
			}
		}
	}
}

func RunForwardRule(info FwdRule) {
	log.Println("Run forward rule:", info)
	if info.Proto == "udp" || info.Proto == "udp6" {
		RunFwdRuleUDP(info)
	} else {
		RunFwdRuleTCP(info)
	}
}

func setupSignalHandler() {
	sigchn := make(chan os.Signal, 1)
	signal.Notify(sigchn, os.Interrupt)
	go func() {
		s := <-sigchn
		log.Println("Signal Received:", s)
		os.Exit(0)
	}()
}

func parseFwdRules(args []string) []FwdRule {
	rules := []FwdRule{}
	for i := range args {
		arg := args[i]
		ruleInfo := strings.Split(arg, ":")
		if len(ruleInfo) < 5 {
			log.Println("Bad Rule:", arg)
			continue
		}
		lp, _ := strconv.Atoi(ruleInfo[2])
		rp, _ := strconv.Atoi(ruleInfo[4])
		rules = append(rules, FwdRule{
			Proto: ruleInfo[0],
			LAddr: ruleInfo[1],
			LPort: lp,
			RAddr: ruleInfo[3],
			RPort: rp,
		})
	}
	return rules
}

func main() {
	setupSignalHandler()
	conf := Config{}
	conf.LoadJson("config.json")
	// log.Println(conf)
	rules := parseFwdRules(os.Args[1:])
	for idx := range rules {
		rule := rules[idx]
		go RunForwardRule(rule)
	}
	for idx := range conf.Rules {
		rule := conf.Rules[idx]
		go RunForwardRule(rule)
	}
	for {
		time.Sleep(1 * time.Second)
	}
}
