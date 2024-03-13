package client

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/aghnet"
	"github.com/AdguardTeam/AdGuardHome/internal/arpdb"
	"github.com/AdguardTeam/AdGuardHome/internal/client/addrproc"
	"github.com/AdguardTeam/AdGuardHome/internal/dhcpsvc"
	"github.com/AdguardTeam/AdGuardHome/internal/dnsforward"
	"github.com/AdguardTeam/AdGuardHome/internal/filtering"
	"github.com/AdguardTeam/AdGuardHome/internal/querylog"
	"github.com/AdguardTeam/AdGuardHome/internal/whois"
	"github.com/AdguardTeam/dnsproxy/proxy"
	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/hostsfile"
	"github.com/AdguardTeam/golibs/log"
	"github.com/AdguardTeam/golibs/stringutil"
	"golang.org/x/exp/maps"
)

// DHCP is an interface for accessing DHCP lease data the [clientsContainer]
// needs.
type DHCP interface {
	// Leases returns all the DHCP leases.
	Leases() (leases []*dhcpsvc.Lease)

	// HostByIP returns the hostname of the DHCP client with the given IP
	// address.  The address will be netip.Addr{} if there is no such client,
	// due to an assumption that a DHCP client must always have a hostname.
	HostByIP(ip netip.Addr) (host string)

	// MACByIP returns the MAC address for the given IP address leased.  It
	// returns nil if there is no such client, due to an assumption that a DHCP
	// client must always have a MAC address.
	MACByIP(ip netip.Addr) (mac net.HardwareAddr)
}

// Storage is the storage of all runtime and persistent clients.
type Storage struct {
	// TODO(a.garipov): Perhaps use a number of separate indices for different
	// types (string, netip.Addr, and so on).
	List map[string]*Persistent // name -> client

	storageConfig *StorageConfig

	ClientIndex *Index

	// IPToRC maps IP addresses to runtime client information.
	IPToRC map[netip.Addr]*Runtime

	allTags *stringutil.Set

	// DHCP is the DHCP service implementation.
	DHCP DHCP

	// DNSServer is used for checking clients IP status access list status
	DNSServer *dnsforward.Server

	// etcHosts contains list of rewrite rules taken from the operating system's
	// hosts database.
	etcHosts *aghnet.HostsContainer

	// arpDB stores the neighbors retrieved from ARP.
	arpDB arpdb.Interface

	// Lock protects all fields.
	//
	// TODO(a.garipov): Use a pointer and describe which fields are protected in
	// more detail.  Use sync.RWMutex.
	Lock sync.Mutex

	// SafeSearchCacheSize is the size of the safe search cache to use for
	// persistent clients.
	SafeSearchCacheSize uint

	// SafeSearchCacheTTL is the TTL of the safe search cache to use for
	// persistent clients.
	SafeSearchCacheTTL time.Duration

	// testing is a flag that disables some features for internal tests.
	//
	// TODO(a.garipov): Awful.  Remove.
	testing bool
}

type StorageConfig struct {
	CustomResolver          func() (safeSearchResolver filtering.Resolver)
	UpstreamTimeout         time.Duration
	UseHostsFile            bool
	BootstrapPreferIPv6     bool
	EDNSClientSubnetEnabled bool
	UseHTTP3Upstreams       bool
}

// Init initializes clients container
// dhcpServer: optional
// Note: this function must be called only once
func (clients *Storage) Init(
	objects []*ClientObject,
	dhcpServer DHCP,
	etcHosts *aghnet.HostsContainer,
	arpDB arpdb.Interface,
	filteringConf *filtering.Config,
	clientTags []string,
	storageConf *StorageConfig,
) (err error) {
	if clients.List != nil {
		log.Fatal("clients.List != nil")
	}

	clients.storageConfig = storageConf

	clients.List = map[string]*Persistent{}
	clients.IPToRC = map[netip.Addr]*Runtime{}

	clients.ClientIndex = NewIndex()

	clients.allTags = stringutil.NewSet(clientTags...)

	// TODO(e.burkov):  Use [dhcpsvc] implementation when it's ready.
	clients.DHCP = dhcpServer

	clients.etcHosts = etcHosts
	clients.arpDB = arpDB
	err = clients.addFromConfig(objects, filteringConf)
	if err != nil {
		// Don't wrap the error, because it's informative enough as is.
		return err
	}

	clients.SafeSearchCacheSize = filteringConf.SafeSearchCacheSize
	clients.SafeSearchCacheTTL = time.Minute * time.Duration(filteringConf.CacheTime)

	if clients.testing {
		return nil
	}

	// The clients.etcHosts may be nil even if config.Clients.Sources.HostsFile
	// is true, because of the deprecated option --no-etc-hosts.
	//
	// TODO(e.burkov):  The option should probably be returned, since hosts file
	// currently used not only for clients' information enrichment, but also in
	// the filtering module and upstream addresses resolution.
	if storageConf.UseHostsFile && clients.etcHosts != nil {
		go clients.handleHostsUpdates()
	}

	return nil
}

// handleHostsUpdates receives the updates from the hosts container and adds
// them to the clients container.  It is intended to be used as a goroutine.
func (clients *Storage) handleHostsUpdates() {
	for upd := range clients.etcHosts.Upd() {
		clients.addFromHostsFile(upd)
	}
}

// Start starts the clients container.
func (clients *Storage) Start() {
	if clients.testing {
		return
	}

	go clients.periodicUpdate()
}

// ReloadARP reloads runtime clients from ARP, if configured.
func (clients *Storage) ReloadARP() {
	if clients.arpDB != nil {
		clients.addFromSystemARP()
	}
}

// ClientObject is the YAML representation of a persistent client.
type ClientObject struct {
	SafeSearchConf filtering.SafeSearchConfig `yaml:"safe_search"`

	// BlockedServices is the configuration of blocked services of a client.
	BlockedServices *filtering.BlockedServices `yaml:"blocked_services"`

	Name string `yaml:"name"`

	IDs       []string `yaml:"ids"`
	Tags      []string `yaml:"tags"`
	Upstreams []string `yaml:"upstreams"`

	// UID is the unique identifier of the persistent client.
	UID UID `yaml:"uid"`

	// UpstreamsCacheSize is the DNS cache size (in bytes).
	//
	// TODO(d.kolyshev): Use [datasize.Bytesize].
	UpstreamsCacheSize uint32 `yaml:"upstreams_cache_size"`

	// UpstreamsCacheEnabled indicates if the DNS cache is enabled.
	UpstreamsCacheEnabled bool `yaml:"upstreams_cache_enabled"`

	UseGlobalSettings        bool `yaml:"use_global_settings"`
	FilteringEnabled         bool `yaml:"filtering_enabled"`
	ParentalEnabled          bool `yaml:"parental_enabled"`
	SafeBrowsingEnabled      bool `yaml:"safebrowsing_enabled"`
	UseGlobalBlockedServices bool `yaml:"use_global_blocked_services"`

	IgnoreQueryLog   bool `yaml:"ignore_querylog"`
	IgnoreStatistics bool `yaml:"ignore_statistics"`
}

// toPersistent returns an initialized persistent client if there are no errors.
func (o *ClientObject) toPersistent(
	filteringConf *filtering.Config,
	allTags *stringutil.Set,
	safeSearchResolver filtering.Resolver,
) (cli *Persistent, err error) {
	cli = &Persistent{
		Name: o.Name,

		Upstreams: o.Upstreams,

		UID: o.UID,

		UseOwnSettings:        !o.UseGlobalSettings,
		FilteringEnabled:      o.FilteringEnabled,
		ParentalEnabled:       o.ParentalEnabled,
		SafeSearchConf:        o.SafeSearchConf,
		SafeBrowsingEnabled:   o.SafeBrowsingEnabled,
		UseOwnBlockedServices: !o.UseGlobalBlockedServices,
		IgnoreQueryLog:        o.IgnoreQueryLog,
		IgnoreStatistics:      o.IgnoreStatistics,
		UpstreamsCacheEnabled: o.UpstreamsCacheEnabled,
		UpstreamsCacheSize:    o.UpstreamsCacheSize,
	}

	err = cli.SetIDs(o.IDs)
	if err != nil {
		return nil, fmt.Errorf("parsing ids: %w", err)
	}

	if (cli.UID == UID{}) {
		cli.UID, err = NewUID()
		if err != nil {
			return nil, fmt.Errorf("generating uid: %w", err)
		}
	}

	if o.SafeSearchConf.Enabled {
		o.SafeSearchConf.CustomResolver = safeSearchResolver

		err = cli.SetSafeSearch(
			o.SafeSearchConf,
			filteringConf.SafeSearchCacheSize,
			time.Minute*time.Duration(filteringConf.CacheTime),
		)
		if err != nil {
			return nil, fmt.Errorf("init safesearch %q: %w", cli.Name, err)
		}
	}

	err = o.BlockedServices.Validate()
	if err != nil {
		return nil, fmt.Errorf("init blocked services %q: %w", cli.Name, err)
	}

	cli.BlockedServices = o.BlockedServices.Clone()

	cli.SetTags(o.Tags, allTags)

	return cli, nil
}

// addFromConfig initializes the clients container with objects from the
// configuration file.
func (clients *Storage) addFromConfig(
	objects []*ClientObject,
	filteringConf *filtering.Config,
) (err error) {
	for i, o := range objects {
		resolver := clients.storageConfig.CustomResolver()

		var cli *Persistent
		cli, err = o.toPersistent(filteringConf, clients.allTags, resolver)
		if err != nil {
			return fmt.Errorf("clients: init persistent client at index %d: %w", i, err)
		}

		_, err = clients.Add(cli)
		if err != nil {
			log.Error("clients: adding client at index %d %s: %s", i, cli.Name, err)
		}
	}

	return nil
}

// ForConfig returns all currently known persistent clients as objects for the
// configuration file.
func (clients *Storage) ForConfig() (objs []*ClientObject) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	objs = make([]*ClientObject, 0, len(clients.List))
	for _, cli := range clients.List {
		o := &ClientObject{
			Name: cli.Name,

			BlockedServices: cli.BlockedServices.Clone(),

			IDs:       cli.IDs(),
			Tags:      stringutil.CloneSlice(cli.Tags),
			Upstreams: stringutil.CloneSlice(cli.Upstreams),

			UID: cli.UID,

			UseGlobalSettings:        !cli.UseOwnSettings,
			FilteringEnabled:         cli.FilteringEnabled,
			ParentalEnabled:          cli.ParentalEnabled,
			SafeSearchConf:           cli.SafeSearchConf,
			SafeBrowsingEnabled:      cli.SafeBrowsingEnabled,
			UseGlobalBlockedServices: !cli.UseOwnBlockedServices,
			IgnoreQueryLog:           cli.IgnoreQueryLog,
			IgnoreStatistics:         cli.IgnoreStatistics,
			UpstreamsCacheEnabled:    cli.UpstreamsCacheEnabled,
			UpstreamsCacheSize:       cli.UpstreamsCacheSize,
		}

		objs = append(objs, o)
	}

	// Maps aren't guaranteed to iterate in the same order each time, so the
	// above loop can generate different orderings when writing to the config
	// file: this produces lots of diffs in config files, so sort objects by
	// name before writing.
	slices.SortStableFunc(objs, func(a, b *ClientObject) (res int) {
		return strings.Compare(a.Name, b.Name)
	})

	return objs
}

// arpClientsUpdatePeriod defines how often ARP clients are updated.
const arpClientsUpdatePeriod = 10 * time.Minute

func (clients *Storage) periodicUpdate() {
	defer log.OnPanic("clients container")

	for {
		clients.ReloadARP()
		time.Sleep(arpClientsUpdatePeriod)
	}
}

// clientSource checks if client with this IP address already exists and returns
// the source which updated it last.  It returns [client.SourceNone] if the
// client doesn't exist.
func (clients *Storage) clientSource(ip netip.Addr) (src Source) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	_, ok := clients.findLocked(ip.String())
	if ok {
		return SourcePersistent
	}

	rc, ok := clients.IPToRC[ip]
	if ok {
		src, _ = rc.Info()
	}

	if src < SourceDHCP && clients.DHCP.HostByIP(ip) != "" {
		src = SourceDHCP
	}

	return src
}

// FindMultiple is a wrapper around [clientsContainer.find] to make it a valid
// client finder for the query log.  c is never nil; if no information about the
// client is found, it returns an artificial client record by only setting the
// blocking-related fields.  err is always nil.
func (clients *Storage) FindMultiple(ids []string) (c *querylog.Client, err error) {
	var artClient *querylog.Client
	var art bool
	for _, id := range ids {
		ip, _ := netip.ParseAddr(id)
		c, art = clients.clientOrArtificial(ip, id)
		if art {
			artClient = c

			continue
		}

		return c, nil
	}

	return artClient, nil
}

// clientOrArtificial returns information about one client.  If art is true,
// this is an artificial client record, meaning that we currently don't have any
// records about this client besides maybe whether or not it is blocked.  c is
// never nil.
func (clients *Storage) clientOrArtificial(
	ip netip.Addr,
	id string,
) (c *querylog.Client, art bool) {
	defer func() {
		c.Disallowed, c.DisallowedRule = clients.DNSServer.IsBlockedClient(ip, id)
		if c.WHOIS == nil {
			c.WHOIS = &whois.Info{}
		}
	}()

	cli, ok := clients.Find(id)
	if ok {
		return &querylog.Client{
			Name:           cli.Name,
			IgnoreQueryLog: cli.IgnoreQueryLog,
		}, false
	}

	var rc *Runtime
	rc, ok = clients.FindRuntimeClient(ip)
	if ok {
		_, host := rc.Info()

		return &querylog.Client{
			Name:  host,
			WHOIS: rc.WHOIS(),
		}, false
	}

	return &querylog.Client{
		Name: "",
	}, true
}

// Find returns a shallow copy of the client if there is one found.
func (clients *Storage) Find(id string) (c *Persistent, ok bool) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	c, ok = clients.findLocked(id)
	if !ok {
		return nil, false
	}

	return c.ShallowClone(), true
}

// ShouldCountClient is a wrapper around [clientsContainer.find] to make it a
// valid client information finder for the statistics.  If no information about
// the client is found, it returns true.
func (clients *Storage) ShouldCountClient(ids []string) (y bool) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	for _, id := range ids {
		client, ok := clients.findLocked(id)
		if ok {
			return !client.IgnoreStatistics
		}
	}

	return true
}

// type check
var _ dnsforward.ClientsContainer = (*Storage)(nil)

// UpstreamConfigByID implements the [dnsforward.ClientsContainer] interface for
// *clientsContainer.  upsConf is nil if the client isn't found or if the client
// has no custom upstreams.
func (clients *Storage) UpstreamConfigByID(
	id string,
	bootstrap upstream.Resolver,
) (conf *proxy.CustomUpstreamConfig, err error) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	c, ok := clients.findLocked(id)
	if !ok {
		return nil, nil
	} else if c.UpstreamConfig != nil {
		return c.UpstreamConfig, nil
	}

	upstreams := stringutil.FilterOut(c.Upstreams, dnsforward.IsCommentOrEmpty)
	if len(upstreams) == 0 {
		return nil, nil
	}

	storageConf := clients.storageConfig

	var upsConf *proxy.UpstreamConfig
	upsConf, err = proxy.ParseUpstreamsConfig(
		upstreams,
		&upstream.Options{
			Bootstrap:    bootstrap,
			Timeout:      storageConf.UpstreamTimeout,
			HTTPVersions: dnsforward.UpstreamHTTPVersions(storageConf.UseHTTP3Upstreams),
			PreferIPv6:   storageConf.BootstrapPreferIPv6,
		},
	)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return nil, err
	}

	conf = proxy.NewCustomUpstreamConfig(
		upsConf,
		c.UpstreamsCacheEnabled,
		int(c.UpstreamsCacheSize),
		storageConf.EDNSClientSubnetEnabled,
	)
	c.UpstreamConfig = conf

	return conf, nil
}

// findLocked searches for a client by its ID.  clients.Lock is expected to be
// locked.
func (clients *Storage) findLocked(id string) (c *Persistent, ok bool) {
	c, ok = clients.ClientIndex.Find(id)
	if ok {
		return c, true
	}

	ip, err := netip.ParseAddr(id)
	if err != nil {
		return nil, false
	}

	// TODO(e.burkov):  Iterate through clients.List only once.
	return clients.findDHCP(ip)
}

// findDHCP searches for a client by its MAC, if the DHCP server is active and
// there is such client.  clients.Lock is expected to be locked.
func (clients *Storage) findDHCP(ip netip.Addr) (c *Persistent, ok bool) {
	foundMAC := clients.DHCP.MACByIP(ip)
	if foundMAC == nil {
		return nil, false
	}

	for _, c = range clients.List {
		_, found := slices.BinarySearchFunc(c.MACs, foundMAC, slices.Compare[net.HardwareAddr])
		if found {
			return c, true
		}
	}

	return nil, false
}

// runtimeClient returns a runtime client from internal index.  Note that it
// doesn't include DHCP clients.
func (clients *Storage) runtimeClient(ip netip.Addr) (rc *Runtime, ok bool) {
	if ip == (netip.Addr{}) {
		return nil, false
	}

	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	rc, ok = clients.IPToRC[ip]

	return rc, ok
}

// FindRuntimeClient finds a runtime client by their IP.
func (clients *Storage) FindRuntimeClient(ip netip.Addr) (rc *Runtime, ok bool) {
	rc, ok = clients.runtimeClient(ip)
	host := clients.DHCP.HostByIP(ip)

	if host != "" {
		if !ok {
			rc = &Runtime{}
		}

		rc.SetInfo(SourceDHCP, []string{host})

		return rc, true
	}

	return rc, ok
}

// check validates the client.  It also sorts the client tags.
func (clients *Storage) check(c *Persistent) (err error) {
	switch {
	case c == nil:
		return errors.Error("client is nil")
	case c.Name == "":
		return errors.Error("invalid name")
	case c.IDsLen() == 0:
		return errors.Error("id required")
	default:
		// Go on.
	}

	for _, t := range c.Tags {
		if !clients.allTags.Has(t) {
			return fmt.Errorf("invalid tag: %q", t)
		}
	}

	// TODO(s.chzhen):  Move to the constructor.
	slices.Sort(c.Tags)

	_, err = proxy.ParseUpstreamsConfig(c.Upstreams, &upstream.Options{})
	if err != nil {
		return fmt.Errorf("invalid upstream servers: %w", err)
	}

	return nil
}

// Add adds a new client object.  ok is false if such client already exists or
// if an error occurred.
func (clients *Storage) Add(c *Persistent) (ok bool, err error) {
	err = clients.check(c)
	if err != nil {
		return false, err
	}

	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	// check Name index
	_, ok = clients.List[c.Name]
	if ok {
		return false, nil
	}

	// check ID index
	err = clients.ClientIndex.Clashes(c)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return false, err
	}

	clients.addLocked(c)

	log.Debug("clients: added %q: ID:%q [%d]", c.Name, c.IDs(), len(clients.List))

	return true, nil
}

// addLocked c to the indexes.  clients.Lock is expected to be locked.
func (clients *Storage) addLocked(c *Persistent) {
	// update Name index
	clients.List[c.Name] = c

	// update ID index
	clients.ClientIndex.Add(c)
}

// Remove removes a client.  ok is false if there is no such client.
func (clients *Storage) Remove(name string) (ok bool) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	var c *Persistent
	c, ok = clients.List[name]
	if !ok {
		return false
	}

	clients.removeLocked(c)

	return true
}

// removeLocked removes c from the indexes.  clients.Lock is expected to be
// locked.
func (clients *Storage) removeLocked(c *Persistent) {
	if err := c.CloseUpstreams(); err != nil {
		log.Error("client container: removing client %s: %s", c.Name, err)
	}

	// Update the name index.
	delete(clients.List, c.Name)

	// Update the ID index.
	clients.ClientIndex.Delete(c)
}

// Update updates a client by its name.
func (clients *Storage) Update(prev, c *Persistent) (err error) {
	err = clients.check(c)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	// Check the name index.
	if prev.Name != c.Name {
		_, ok := clients.List[c.Name]
		if ok {
			return errors.Error("client already exists")
		}
	}

	if c.EqualIDs(prev) {
		clients.removeLocked(prev)
		clients.addLocked(c)

		return nil
	}

	// Check the ID index.
	err = clients.ClientIndex.Clashes(c)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	clients.removeLocked(prev)
	clients.addLocked(c)

	return nil
}

// setWHOISInfo sets the WHOIS information for a client.  clients.Lock is
// expected to be locked.
func (clients *Storage) setWHOISInfo(ip netip.Addr, wi *whois.Info) {
	_, ok := clients.findLocked(ip.String())
	if ok {
		log.Debug("clients: client for %s is already created, ignore whois info", ip)

		return
	}

	rc, ok := clients.IPToRC[ip]
	if !ok {
		// Create a RuntimeClient implicitly so that we don't do this check
		// again.
		rc = &Runtime{}
		clients.IPToRC[ip] = rc

		log.Debug("clients: set whois info for runtime client with ip %s: %+v", ip, wi)
	} else {
		host, _ := rc.Info()
		log.Debug("clients: set whois info for runtime client %s: %+v", host, wi)
	}

	rc.SetWHOIS(wi)
}

// addHost adds a new IP-hostname pairing.  The priorities of the sources are
// taken into account.  ok is true if the pairing was added.
//
// TODO(a.garipov): Only used in internal tests.  Consider removing.
func (clients *Storage) addHost(
	ip netip.Addr,
	host string,
	src Source,
) (ok bool) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	return clients.addHostLocked(ip, host, src)
}

// type check
var _ addrproc.AddressUpdater = (*Storage)(nil)

// UpdateAddress implements the [client.AddressUpdater] interface for
// *clientsContainer
func (clients *Storage) UpdateAddress(ip netip.Addr, host string, info *whois.Info) {
	// Common fast path optimization.
	if host == "" && info == nil {
		return
	}

	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	if host != "" {
		ok := clients.addHostLocked(ip, host, SourceRDNS)
		if !ok {
			log.Debug("clients: host for client %q already set with higher priority source", ip)
		}
	}

	if info != nil {
		clients.setWHOISInfo(ip, info)
	}
}

// addHostLocked adds a new IP-hostname pairing.  clients.Lock is expected to be
// locked.
func (clients *Storage) addHostLocked(
	ip netip.Addr,
	host string,
	src Source,
) (ok bool) {
	rc, ok := clients.IPToRC[ip]
	if !ok {
		if src < SourceDHCP {
			if clients.DHCP.HostByIP(ip) != "" {
				return false
			}
		}

		rc = &Runtime{}
		clients.IPToRC[ip] = rc
	}

	rc.SetInfo(src, []string{host})

	log.Debug("clients: adding client info %s -> %q %q [%d]", ip, src, host, len(clients.IPToRC))

	return true
}

// rmHostsBySrc removes all entries that match the specified source.
func (clients *Storage) rmHostsBySrc(src Source) {
	n := 0
	for ip, rc := range clients.IPToRC {
		rc.Unset(src)
		if rc.IsEmpty() {
			delete(clients.IPToRC, ip)
			n++
		}
	}

	log.Debug("clients: removed %d client aliases", n)
}

// addFromHostsFile fills the client-hostname pairing index from the system's
// hosts files.
func (clients *Storage) addFromHostsFile(hosts *hostsfile.DefaultStorage) {
	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	clients.rmHostsBySrc(SourceHostsFile)

	n := 0
	hosts.RangeNames(func(addr netip.Addr, names []string) (cont bool) {
		// Only the first name of the first record is considered a canonical
		// hostname for the IP address.
		//
		// TODO(e.burkov):  Consider using all the names from all the records.
		if clients.addHostLocked(addr, names[0], SourceHostsFile) {
			n++
		}

		return true
	})

	log.Debug("clients: added %d client aliases from system hosts file", n)
}

// addFromSystemARP adds the IP-hostname pairings from the output of the arp -a
// command.
func (clients *Storage) addFromSystemARP() {
	if err := clients.arpDB.Refresh(); err != nil {
		log.Error("refreshing arp container: %s", err)

		clients.arpDB = arpdb.Empty{}

		return
	}

	ns := clients.arpDB.Neighbors()
	if len(ns) == 0 {
		log.Debug("refreshing arp container: the update is empty")

		return
	}

	clients.Lock.Lock()
	defer clients.Lock.Unlock()

	clients.rmHostsBySrc(SourceARP)

	added := 0
	for _, n := range ns {
		if clients.addHostLocked(n.IP, n.Name, SourceARP) {
			added++
		}
	}

	log.Debug("clients: added %d client aliases from arp neighborhood", added)
}

// Close gracefully closes all the client-specific upstream configurations of
// the persistent clients.
func (clients *Storage) Close() (err error) {
	persistent := maps.Values(clients.List)
	slices.SortFunc(persistent, func(a, b *Persistent) (res int) {
		return strings.Compare(a.Name, b.Name)
	})

	var errs []error

	for _, cli := range persistent {
		if err = cli.CloseUpstreams(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
