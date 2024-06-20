package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/honeycombio/refinery/config"
	"github.com/honeycombio/refinery/internal/redimem"
	"github.com/redis/go-redis/v9"
	"github.com/sirupsen/logrus"
)

const (
	// refreshCacheInterval is how frequently this host will re-register itself
	// with Redis. This should happen about 3x during each timeout phase in order
	// to allow multiple timeouts to fail and yet still keep the host in the mix.
	// Falling out of Redis will result in re-hashing the host-trace affinity and
	// will cause broken traces for those that fall on both sides of the rehashing.
	// This is why it's important to ensure hosts stay in the pool.
	refreshCacheInterval = 3 * time.Second

	// peerEntryTimeout is how long redis will wait before expiring a peer that
	// doesn't check in. The ratio of refresh to peer timeout should be 1/3. Redis
	// timeouts are in seconds and entries can last up to 2 seconds longer than
	// their expected timeout (in my load testing), so the lower bound for this
	// timer should be ... 5sec?
	peerEntryTimeout = 10 * time.Second
)

type redisPeers struct {
	store      *redimem.RedisMembership
	peers      []string
	peerLock   sync.Mutex
	c          config.Config
	callbacks  []func()
	publicAddr string
}

// NewRedisPeers returns a peers collection backed by redis
func newRedisPeers(ctx context.Context, c config.Config, done chan struct{}) (Peers, error) {
	// deal with this error
	address, err := publicAddr(c)

	if err != nil {
		return nil, err
	}

	connType, _ := c.GetRedisClientType()

	var redisClient redis.Cmdable
	switch strings.ToLower(connType) {
	case "cluster":
		redisClient, err = buildClusterClient(c)
	case "sentinel":
		redisClient, err = buildSentinelClient(c)
	case "standalone":
		redisClient, err = buildStandaloneClient(c)
	default:
		return nil, errors.New(fmt.Sprintf("Redis client type '%s' is not valid.", connType))
	}

	if err != nil {
		return nil, err
	}

	peers := &redisPeers{
		store: &redimem.RedisMembership{
			Prefix: c.GetRedisPrefix(),
			Client: redisClient,
		},
		peers:      make([]string, 1),
		c:          c,
		callbacks:  make([]func(), 0),
		publicAddr: address,
	}

	// register myself once
	err = peers.store.Register(ctx, address, peerEntryTimeout)
	if err != nil {
		logrus.WithError(err).Errorf("failed to register self with redis peer store")
		return nil, err
	}

	// go establish a regular registration heartbeat to ensure I stay alive in redis
	go peers.registerSelf(done)

	// get our peer list once to seed ourselves
	peers.updatePeerListOnce()

	// go watch the list of peers and trigger callbacks whenever it changes.
	// populate my local list of peers so each request can hit memory and only hit
	// redis on a ticker
	go peers.watchPeers(done)

	return peers, nil
}

func buildSentinelClient(c config.Config) (*redis.Client, error) {
	opt := &redis.FailoverOptions{}

	username, _ := c.GetRedisUsername()
	if username != "" {
		opt.Username = username
	}

	password, _ := c.GetRedisPassword()
	if password != "" {
		opt.Password = password
	}

	sentinelMaster, err := c.GetRedisSentinelMasterName()
	if err != nil {
		return nil, err
	}
	opt.MasterName = sentinelMaster

	sentinelHosts, _ := c.GetRedisSentinelHosts()
	if len(sentinelHosts) == 0 {
		sentinelHosts = []string{"localhost:6379"}
	}
	opt.SentinelAddrs = sentinelHosts

	sentinelPassword, _ := c.GetRedisSentinelPassword()
	if sentinelPassword != "" {
		opt.SentinelPassword = sentinelPassword
	}

	tlsConfig, err := createTLSConfig(c)
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		opt.TLSConfig = tlsConfig
	}

	opt.DB = c.GetRedisDatabase()

	opt.DialTimeout = time.Second

	return redis.NewFailoverClient(opt), nil
}

func buildStandaloneClient(c config.Config) (*redis.Client, error) {
	opt := &redis.Options{}

	username, _ := c.GetRedisUsername()
	if username != "" {
		opt.Username = username
	}

	password, _ := c.GetRedisPassword()
	if password != "" {
		opt.Password = password
	}

	redisHost, _ := c.GetRedisHost()
	if len(redisHost) == 0 {
		redisHost = "localhost:6379"
	}
	opt.Addr = redisHost

	tlsConfig, err := createTLSConfig(c)
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		opt.TLSConfig = tlsConfig
	}

	opt.DB = c.GetRedisDatabase()

	opt.DialTimeout = 1 * time.Second

	return redis.NewClient(opt), nil
}

func buildClusterClient(c config.Config) (*redis.ClusterClient, error) {
	opt := &redis.ClusterOptions{}

	hosts, _ := c.GetRedisClusterHosts()
	if len(hosts) == 0 {
		hosts = []string{"localhost:6379"}
	}
	opt.Addrs = hosts

	username, _ := c.GetRedisUsername()
	if username != "" {
		opt.Username = username
	}

	password, _ := c.GetRedisPassword()
	if password != "" {
		opt.Password = password
	}

	tlsConfig, err := createTLSConfig(c)
	if err != nil {
		return nil, err
	}

	if tlsConfig != nil {
		opt.TLSConfig = tlsConfig
	}

	opt.DialTimeout = 1 * time.Second

	return redis.NewClusterClient(opt), nil
}

func createTLSConfig(c config.Config) (*tls.Config, error) {
	var tlsConfig *tls.Config

	useTLS, _ := c.GetUseTLS()
	tlsInsecure, _ := c.GetUseTLSInsecure()
	if useTLS {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}

		if tlsInsecure {
			tlsConfig.InsecureSkipVerify = true
		}
	}

	return tlsConfig, nil
}

func (p *redisPeers) GetPeers() ([]string, error) {
	p.peerLock.Lock()
	defer p.peerLock.Unlock()
	retList := make([]string, len(p.peers))
	copy(retList, p.peers)
	return retList, nil
}

func (p *redisPeers) RegisterUpdatedPeersCallback(cb func()) {
	p.callbacks = append(p.callbacks, cb)
}

// registerSelf inserts self into the peer list and updates self's entry on a
// regular basis so it doesn't time out and get removed from the list of peers.
// When this function stops, it tries to remove the registered key.
func (p *redisPeers) registerSelf(done chan struct{}) {
	tk := time.NewTicker(refreshCacheInterval)
	for {
		select {
		case <-tk.C:
			ctx, cancel := context.WithTimeout(context.Background(), p.c.GetPeerTimeout())
			// every interval, insert a timeout record. we ignore the error
			// here since Register() logs the error for us.
			p.store.Register(ctx, p.publicAddr, peerEntryTimeout)
			cancel()
		case <-done:
			// unregister ourselves
			ctx, cancel := context.WithTimeout(context.Background(), p.c.GetPeerTimeout())
			p.store.Unregister(ctx, p.publicAddr)
			cancel()
			return
		}
	}
}

func (p *redisPeers) updatePeerListOnce() {
	ctx, cancel := context.WithTimeout(context.Background(), p.c.GetPeerTimeout())
	defer cancel()

	currentPeers, err := p.store.GetMembers(ctx)
	if err != nil {
		logrus.WithError(err).
			WithFields(logrus.Fields{
				"name":    p.publicAddr,
				"timeout": p.c.GetPeerTimeout().String(),
			}).
			Error("get members failed")
		return
	}
	sort.Strings(currentPeers)
	// update peer list and trigger callbacks saying the peer list has changed
	p.peerLock.Lock()
	p.peers = currentPeers
	p.peerLock.Unlock()
}

func (p *redisPeers) watchPeers(done chan struct{}) {
	oldPeerList := p.peers
	sort.Strings(oldPeerList)
	tk := time.NewTicker(refreshCacheInterval)

	for {
		select {
		case <-tk.C:
			ctx, cancel := context.WithTimeout(context.Background(), p.c.GetPeerTimeout())
			currentPeers, err := p.store.GetMembers(ctx)
			cancel()

			if err != nil {
				logrus.WithError(err).
					WithFields(logrus.Fields{
						"name":     p.publicAddr,
						"timeout":  p.c.GetPeerTimeout().String(),
						"oldPeers": oldPeerList,
					}).
					Error("get members failed during watch")
				continue
			}

			sort.Strings(currentPeers)
			if !equal(oldPeerList, currentPeers) {
				// update peer list and trigger callbacks saying the peer list has changed
				p.peerLock.Lock()
				p.peers = currentPeers
				oldPeerList = currentPeers
				p.peerLock.Unlock()
				for _, callback := range p.callbacks {
					// don't block on any of the callbacks.
					go callback()
				}
			}
		case <-done:
			p.peerLock.Lock()
			p.peers = []string{}
			p.peerLock.Unlock()
			return
		}
	}
}

func publicAddr(c config.Config) (string, error) {
	// compute the public version of my peer listen address
	listenAddr, _ := c.GetPeerListenAddr()
	_, port, err := net.SplitHostPort(listenAddr)

	if err != nil {
		return "", err
	}

	var myIdentifier string

	// If RedisIdentifier is set, use as identifier.
	if redisIdentifier, _ := c.GetRedisIdentifier(); redisIdentifier != "" {
		myIdentifier = redisIdentifier
		logrus.WithField("identifier", myIdentifier).Info("using specified RedisIdentifier from config")
	} else {
		// Otherwise, determine identifier from network interface.
		myIdentifier, err = getIdentifierFromInterfaces(c)
		if err != nil {
			return "", err
		}
	}

	publicListenAddr := fmt.Sprintf("http://%s:%s", myIdentifier, port)

	return publicListenAddr, nil
}

// Scan network interfaces to determine an identifier from either IP or hostname.
func getIdentifierFromInterfaces(c config.Config) (string, error) {
	myIdentifier, _ := os.Hostname()
	identifierInterfaceName, _ := c.GetIdentifierInterfaceName()

	if identifierInterfaceName != "" {
		ifc, err := net.InterfaceByName(identifierInterfaceName)
		if err != nil {
			logrus.WithError(err).WithField("interface", identifierInterfaceName).
				Error("IdentifierInterfaceName set but couldn't find interface by that name")
			return "", err
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			logrus.WithError(err).WithField("interface", identifierInterfaceName).
				Error("IdentifierInterfaceName set but couldn't list addresses")
			return "", err
		}
		var ipStr string
		for _, addr := range addrs {
			// ParseIP doesn't know what to do with the suffix
			ip := net.ParseIP(strings.Split(addr.String(), "/")[0])
			ipv6, _ := c.GetUseIPV6Identifier()
			if ipv6 && ip.To16() != nil {
				ipStr = fmt.Sprintf("[%s]", ip.String())
				break
			}
			if !ipv6 && ip.To4() != nil {
				ipStr = ip.String()
				break
			}
		}
		if ipStr == "" {
			err = errors.New("could not find a valid IP to use from interface")
			logrus.WithField("interface", ifc.Name).WithError(err)
			return "", err
		}
		myIdentifier = ipStr
		logrus.WithField("identifier", myIdentifier).WithField("interface", ifc.Name).Info("using identifier from interface")
	}

	return myIdentifier, nil
}

// equal tells whether a and b contain the same elements.
// A nil argument is equivalent to an empty slice.
// lifted from https://yourbasic.org/golang/compare-slices/
func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
