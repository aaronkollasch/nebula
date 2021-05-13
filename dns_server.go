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
var dnsSoa *dns.SOA
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
		zone := plugin.Zones(dnsZones).Matches(q.Name)
		switch q.Qtype {
		case dns.TypeA:
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
			if (zone == "" || dnsSoa == nil) && !dnsR.hostMap.vpnCIDR.Contains(b) && a != "127.0.0.1" {
				return fmt.Errorf("Dropped query for TXT %s", q.Name)
			}
			l.Debugf("Accepted query for TXT %s", q.Name)
			if !dnsR.hostMap.vpnCIDR.Contains(b) && a != "127.0.0.1" {
				ip := dnsR.QueryCert(q.Name)
				if ip != "" {
					rr, err := dns.NewRR(fmt.Sprintf("%s TXT %s", q.Name, ip))
					if err == nil {
						m.Answer = append(m.Answer, rr)
					}
				}
			}
		case dns.TypeDNSKEY:
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
		case dns.TypeSOA:
			if zone == "" || dnsSoa == nil {
				return fmt.Errorf("Dropped query for SOA %s", q.Name)
			}
			rr := dns.Copy(dnsSoa)
			rr.Header().Name = zone
			m.Answer = append(m.Answer, rr)
			m.Authoritative = true
			l.Debugf("Accepted query for SOA %s", q.Name)
		case dns.TypeNS:
			if zone == "" || dnsSoa == nil {
                                return fmt.Errorf("Dropped query for NS %s", q.Name)
                        }
			rr, err := dns.NewRR(fmt.Sprintf("%s NS %s", zone, dnsSoa.Ns))
			if err == nil {
				m.Answer = append(m.Answer, rr)
				m.Authoritative = true
			}
			l.Debugf("Accepted query for NS %s", q.Name)
		default:
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
	default:
		return
	}

	r.Answer = append(r.Answer, m.Answer...)
	r.Authoritative = m.Authoritative
	//parseQuery currently only sets m.Answer, not Ns or Extra. This could change.

	state := request.Request{W: w, Req: r}
	zone := plugin.Zones(dnsZones).Matches(state.Name())
	if len(dnsKeys) > 0 && state.Do() && zone != "" {
		state.Zone = zone
		r = dnsSec.Sign(state, time.Now().UTC(), "")
		m.Answer = r.Answer
		m.Ns = r.Ns
		m.Extra = r.Extra
	}

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
	zones := c.GetStringSlice("lighthouse.dns.zones", []string{})
	for i := range zones {
		zones[i] = dns.CanonicalName(zones[i])
	}
	return zones
}

func getDnsSoa(c *Config) *dns.SOA {
	serial := c.GetInt("lighthouse.dns.soa.serial", 0)
	if serial == 0 {
		return nil
	}
	header := dns.RR_Header{
		Name: c.GetString("lighthouse.dns.soa.name", ""),
		Rrtype: dns.TypeSOA,
		Class: dns.ClassINET,
		Ttl: uint32(c.GetInt("lighthouse.dns.soa.ttl", 3600)),
	}
	return &dns.SOA{
		Hdr: header,
		Ns: c.GetString("lighthouse.dns.soa.mname", ""),
		Mbox: c.GetString("lighthouse.dns.soa.rname", ""),
		Serial: uint32(serial),
		Refresh: uint32(c.GetInt("lighthouse.dns.soa.refresh", 900)),
		Retry: uint32(c.GetInt("lighthouse.dns.soa.retry", 900)),
		Expire: uint32(c.GetInt("lighthouse.dns.soa.expire", 3600)),
		Minttl: uint32(c.GetInt("lighthouse.dns.soa.minimum", 3600)),
	}
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

func dnssecParse(l *logrus.Logger, ks []string) {
	err := errors.New("")
	dnsKeys, err = keyParse(ks)
	if err != nil {
		l.WithError(err).Errorf("Failed to load DNSSEC keys")
	} else {
		for _, k := range dnsKeys {
			l.WithField("key", k.K.String()).WithField("tag", k.K.KeyTag()).Info("Loaded DNSSEC key")
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
			l.WithField("key", k.K.String()).WithField("tag", k.K.KeyTag()).Error("Did not accept DNSSEC key")
		}
	}
	capacity := 10000
	dnsSec = dnssec.New(dnsZones, dnsKeys, splitkeys, nil, dns_cache.New(capacity))
}

func startDns(l *logrus.Logger, c *Config) {
	dnsAddr = getDnsServerAddr(c)
	dnsZones = getDnsZones(c)
	dnsSoa = getDnsSoa(c)
	ks := getDnsKeys(c)
	dnssecParse(l, ks)
	dnsServer = &dns.Server{Addr: dnsAddr, Net: "udp"}
	l.WithField("dnsListener", dnsAddr).Infof("Starting DNS responder")
	err := dnsServer.ListenAndServe()
	defer dnsServer.Shutdown()
	if err != nil {
		l.Errorf("Failed to start server: %s\n ", err.Error())
	}
}

func reloadDns(l *logrus.Logger, c *Config) {
	l.Debug("Restarting DNS server")
	dnsServer.Shutdown()
	go startDns(l, c)
}
