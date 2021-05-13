package nebula

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"strings"
	"errors"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
	"github.com/coredns/coredns/plugin/dnssec"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	dns_cache "github.com/coredns/coredns/plugin/pkg/cache"
)

// This whole thing should be rewritten to use context

var dnsR *dnsRecords
var dnsServer *dns.Server
var dnsAddr string
var dnsZones []string
var dnsKeys []*dnssec.DNSKEY
var dnsSec dnssec.Dnssec

type dnsRecords struct {
	sync.RWMutex
	dnsMap  map[string]string
	hostMap *HostMap
}

func newDnsRecords(hostMap *HostMap) *dnsRecords {
	return &dnsRecords{
		dnsMap:  make(map[string]string),
		hostMap: hostMap,
	}
}

func (d *dnsRecords) Query(data string) string {
	d.RLock()
	if r, ok := d.dnsMap[data]; ok {
		d.RUnlock()
		return r
	}
	d.RUnlock()
	return ""
}

func (d *dnsRecords) QueryCert(data string) string {
	ip := net.ParseIP(data[:len(data)-1])
	if ip == nil {
		return ""
	}
	iip := ip2int(ip)
	hostinfo, err := d.hostMap.QueryVpnIP(iip)
	if err != nil {
		return ""
	}
	q := hostinfo.GetCert()
	if q == nil {
		return ""
	}
	cert := q.Details
	c := fmt.Sprintf("\"Name: %s\" \"Ips: %s\" \"Subnets %s\" \"Groups %s\" \"NotBefore %s\" \"NotAFter %s\" \"PublicKey %x\" \"IsCA %t\" \"Issuer %s\"", cert.Name, cert.Ips, cert.Subnets, cert.Groups, cert.NotBefore, cert.NotAfter, cert.PublicKey, cert.IsCA, cert.Issuer)
	return c
}

func (d *dnsRecords) Add(host, data string) {
	d.Lock()
	d.dnsMap[host] = data
	d.Unlock()
}

func parseQuery(l *logrus.Logger, m *dns.Msg, w dns.ResponseWriter) error {
	for _, q := range m.Question {
		switch q.Qtype {
		case dns.TypeA:
			zone := plugin.Zones(dnsZones).Matches(q.Name)
			if zone == "" {
				return fmt.Errorf("Dropped query for A %s", q.Name)
			}
			l.Debugf("Accepted query for A %s", q.Name)
			ip := dnsR.Query(q.Name)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
					m.Authoritative = true
				}
			}
		case dns.TypeTXT:
			a, _, _ := net.SplitHostPort(w.RemoteAddr().String())
			b := net.ParseIP(a)
			// We don't answer these queries from non nebula nodes or localhost
			//l.Debugf("Does %s contain %s", b, dnsR.hostMap.vpnCIDR)
			if !dnsR.hostMap.vpnCIDR.Contains(b) && a != "127.0.0.1" {
				return fmt.Errorf("Dropped query for TXT %s", q.Name)
			}
			l.Debugf("Accepted query for TXT %s", q.Name)
			ip := dnsR.QueryCert(q.Name)
			if ip != "" {
				rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, ip))
				if err == nil {
					m.Answer = append(m.Answer, rr)
				}
			}
		case dns.TypeDNSKEY:
			zone := plugin.Zones(dnsZones).Matches(q.Name)
			if zone == "" {
				return fmt.Errorf("Dropped query for DNSKEY %s", q.Name)
			}
			keys := make([]dns.RR, len(dnsKeys))
			for i, k := range dnsKeys {
				keys[i] = dns.Copy(k.K)
				keys[i].Header().Name = zone
			}
			m.Answer = keys
			m.Authoritative = true
			l.Debugf("Accepted query for DNSKEY %s", q.Name)
		default:
			zone := plugin.Zones(dnsZones).Matches(q.Name)
			if zone == "" {
				return fmt.Errorf("Dropped query for %s %s", dns.Type(q.Qtype).String(), q.Name)
			}
			l.Debugf("Unsupported query for %s %s", dns.Type(q.Qtype).String(), q.Name)
		}
	}
	return nil
}

func handleDnsRequest(l *logrus.Logger, w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		err := parseQuery(l, m, w)
		if err != nil {
		       l.Debug(err.Error())
		       return
		}
	}

	r.Answer = append(r.Answer, m.Answer...)
	state := request.Request{W: w, Req: r}
	if len(dnsKeys) > 0 && state.Do() {
		zone := plugin.Zones(dnsZones).Matches(state.Name())
		if zone == "" {
			w.WriteMsg(m)
			return
		}
		state.Zone = zone
		r = dnsSec.Sign(state, time.Now().UTC(), "")
	}

	m.Answer = r.Answer
	w.WriteMsg(m)
}


func dnsMain(l *logrus.Logger, hostMap *HostMap, c *Config) func() {
	dnsR = newDnsRecords(hostMap)

	// attach request handler func
	dns.HandleFunc(".", func(w dns.ResponseWriter, r *dns.Msg) {
		handleDnsRequest(l, w, r)
	})

	c.RegisterReloadCallback(func(c *Config) {
		reloadDns(l, c)
	})

	return func() {
		startDns(l, c)
	}
}

func getDnsServerAddr(c *Config) string {
	return c.GetString("lighthouse.dns.host", "") + ":" + strconv.Itoa(c.GetInt("lighthouse.dns.port", 53))
}

func getDnsZones(c *Config) []string {
	return c.GetStringSlice("lighthouse.dns.zones", []string{})
}

func keyParse(ks []string) ([]*dnssec.DNSKEY, error) {
	keys := []*dnssec.DNSKEY{}
	for _, k := range ks {
		base := k
		if strings.HasSuffix(k, ".key") {
			base = k[:len(k)-4]
		}
		if strings.HasSuffix(k, ".private") {
			base = k[:len(k)-8]
		}
		k, err := dnssec.ParseKeyFile(base+".key", base+".private")
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

func getDnsKeys(c *Config) []string {
	return c.GetStringSlice("lighthouse.dns.dnssec_keys", []string{})
}


func isZSK(k dnssec.DNSKEY) bool {
	return k.K.Flags&(1<<8) == (1<<8) && k.K.Flags&1 == 0
}

func isKSK(k dnssec.DNSKEY) bool {
        return k.K.Flags&(1<<8) == (1<<8) && k.K.Flags&1 == 1
}

func dnssecParse(l *logrus.Logger, c *Config) {
	dnsZones = getDnsZones(c)
	ks := getDnsKeys(c)
	err := errors.New("")
	dnsKeys, err = keyParse(ks)
	if err != nil {
		l.Debug(err.Error())
	} else {
		for _, k := range dnsKeys {
			l.WithField("key", k.K.String()).Info("loaded key")
		}
	}
	zsk, ksk := 0,0
	for _, k := range dnsKeys {
		if isKSK(*k) {
			ksk++
		} else if isZSK(*k) {
			zsk++
		}
	}
	splitkeys := zsk > 0 && ksk > 0

	for _, k := range dnsKeys {
		kname := plugin.Name(k.K.Header().Name)
		ok := false
		for i := range dnsZones {
			if kname.Matches(dnsZones[i]) {
				ok = true
				break
			}
		}
		if !ok {
			l.WithField("key", k.K.String()).Debug("did not accept key")
		}
	}
	capacity := 10000
	dnsSec = dnssec.New(dnsZones, dnsKeys, splitkeys, nil, dns_cache.New(capacity))
}

func startDns(l *logrus.Logger, c *Config) {
	dnsAddr = getDnsServerAddr(c)
	dnssecParse(l, c)
	dnsServer = &dns.Server{Addr: dnsAddr, Net: "udp"}
	l.WithField("dnsListener", dnsAddr).Infof("Starting DNS responder")
	err := dnsServer.ListenAndServe()
	defer dnsServer.Shutdown()
	if err != nil {
		l.Errorf("Failed to start server: %s\n ", err.Error())
	}
}

func reloadDns(l *logrus.Logger, c *Config) {
	if dnsAddr == getDnsServerAddr(c) {
		l.Debug("No DNS server config change detected")
		return
	}

	l.Debug("Restarting DNS server")
	dnsServer.Shutdown()
	go startDns(l, c)
}
