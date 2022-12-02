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

type wListItem struct {
	wlType int
	n      *net.IPNet
	ip     []net.IP
}

type FwdRule struct {
	Enable  bool   `json:"enable"`
	Proto   string `json:"proto"`
	LAddr   string `json:"lAddr"`
	LPort   int    `json:"lPort"`
	Backend string `json:"backend"`
	bkend   *Backend
	RAddr   string `json:"rAddr"`
	RPort   int    `json:"rPort"`
	WList   string `json:"whitelist"`
	wl      []wListItem
}

func (r *FwdRule) CheckIp(ip net.IP) bool {
	if len(r.wl) == 0 {
		log.Println("Empty wl to check ip", ip)
		return true
	}

	for i := range r.wl {
		if r.wl[i].wlType == 1 && r.wl[i].n.Contains(ip) {
			return true
		}
		if r.wl[i].wlType == 2 {
			for j := range r.wl[i].ip {
				if r.wl[i].ip[j].Equal(ip) {
					return true
				}
			}
		}
	}
	return false
}

type Config struct {
	Rules    []FwdRule           `json:"rules"`
	Backends map[string]*Backend `json:"backends"`
	IpSetMap map[string][]string `json:"ipsets"`
}

func (c *Config) LoadFromFile(filename string) {
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

	wlMap := make(map[string][]wListItem)

	// Process items in ipset to internal format
	for name, strWl := range c.IpSetMap {
		wlItem := make([]wListItem, len(strWl))
		for i := range strWl {
			_, ipnet, err := net.ParseCIDR(strWl[i])
			if err == nil {
				wlItem[i] = wListItem{
					wlType: 1,
					n:      ipnet,
				}
				continue
			}
			ips, err := net.LookupIP(strWl[i])
			if err == nil {
				wlItem[i] = wListItem{
					wlType: 2,
					ip:     ips,
				}
				continue
			}
			log.Println("Failed to process", strWl[i])
		}
		wlMap[name] = wlItem
	}

	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.Backend != "" {
			rule.bkend = c.Backends[rule.Backend]
		}
	}

	// set wlist items into rules
	for i := range c.Rules {
		rule := &c.Rules[i]
		if rule.WList == "" {
			continue
		}
		rule.wl = make([]wListItem, 0)
		names := strings.Split(rule.WList, ",")
		for i := range names {
			name := strings.Trim(names[i], " ")
			if name == "" {
				continue
			}
			ipnets, exists := wlMap[name]
			if exists {
				rule.wl = append(rule.wl, ipnets...)
			} else {
				log.Println("Invalid ipset name", name)
			}
		}
	}
}

type TCPFwdEntry struct {
	rule  FwdRule
	connL net.Conn
	connR net.Conn
}

func (e *TCPFwdEntry) L2R() {
	defer e.connL.Close()
	buf := make([]byte, 2048)
	for {
		n, err := e.connL.Read(buf)
		if err != nil {
			log.Println("TCP L2R", err)
			e.connR.Close()
			return
		}
		_, err = e.connR.Write(buf[:n])
		if err != nil {
			log.Println("TCP L2R", err)
			e.connR.Close()
			return
		}
	}
}

func (e *TCPFwdEntry) R2L() {
	defer e.connR.Close()
	buf := make([]byte, 2048)
	for {
		n, err := e.connR.Read(buf)
		if err != nil {
			log.Println("TCP R2L", err)
			e.connL.Close()
			return
		}
		_, err = e.connL.Write(buf[:n])
		if err != nil {
			log.Println("TCP R2L", err)
			e.connL.Close()
			return
		}
	}
}

func (e *TCPFwdEntry) Run() {
	var addr string
	if e.rule.bkend != nil {
		rhost := e.rule.bkend.GetRHost()
		if rhost == nil {
			log.Println("get rhost failed")
			e.connL.Close()
			return
		}
		addr = fmt.Sprintf("%s:%d", rhost.RAddr, rhost.RPort)
	} else {
		addr = fmt.Sprintf("%s:%d", e.rule.RAddr, e.rule.RPort)
	}
	log.Println("TCP Connecting", addr)
	connR, err := net.Dial(e.rule.Proto, addr)
	if err != nil {
		log.Println("Dial remote failed", err)
		e.connL.Close()
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
		log.Println("New TCP connection from", conn.RemoteAddr())
		rIpStr := conn.RemoteAddr().String()
		host, _, err := net.SplitHostPort(rIpStr)
		if err != nil {
			conn.Close()
			continue
		}
		ip := net.ParseIP(host)
		if !rule.CheckIp(ip) {
			log.Printf("Remote IP [%s] not in allowed list, close connection.\n", host)
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
	defer connL.Close()

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
	if !info.Enable {
		// log.Println("Ignore unenabled rule:", info)
		return
	}
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
			Enable: true,
			Proto:  ruleInfo[0],
			LAddr:  ruleInfo[1],
			LPort:  lp,
			RAddr:  ruleInfo[3],
			RPort:  rp,
		})
	}
	return rules
}

func main() {
	setupSignalHandler()
	conf := Config{}
	conf.LoadFromFile("config.json")
	// log.Println(conf)
	rules := parseFwdRules(os.Args[1:])

	// run backend detect
	for k := range conf.Backends {
		log.Println("running detector", k)
		bend := conf.Backends[k]
		go bend.Detect()
	}
	// run command line rules
	for idx := range rules {
		rule := rules[idx]
		go RunForwardRule(rule)
	}
	// run config file rules
	for idx := range conf.Rules {
		rule := conf.Rules[idx]
		go RunForwardRule(rule)
	}
	for {
		time.Sleep(1 * time.Second)
	}
}
