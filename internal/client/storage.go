package client

import (
	"net/netip"

	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
)

// Storage stores information about runtime and persistent clients.
type Storage struct {
	// runtimeIndex stores information about runtime clients.
	runtimeIndex map[netip.Addr]*Runtime

	// index stores all information about persistent clients.
	index *Index
}

// NewStorage returns initialized client storage.
func NewStorage() (s *Storage) {
	return &Storage{
		index:        NewIndex(),
		runtimeIndex: map[netip.Addr]*Runtime{},
	}
}

// Size returns the size of the persistent client list.
func (s *Storage) Size() (n int) {
	return len(s.index.uidToClient)
}

// Find finds persistent client by string representation of the client ID, IP
// address, or MAC.
func (s *Storage) Find(id string) (c *Persistent, ok bool) {
	return s.index.Find(id)
}

// FindByName finds a persistent client by name.
func (s *Storage) FindByName(name string) (c *Persistent, ok bool) {
	return s.index.findByName(name)
}

// Add adds a new persistent client.  ok is false if such client already exists
// or if an error occurred.
func (s *Storage) Add(c *Persistent) (ok bool, err error) {
	_, found := s.index.findByName(c.Name)
	if found {
		return false, nil
	}

	err = s.index.Clashes(c)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return false, err
	}

	s.add(c)

	return true, nil
}

// add c to the indexes.
func (s *Storage) add(c *Persistent) {
	s.index.Add(c)
}

// Remove removes a persistent client.  ok is false if there is no such client.
func (s *Storage) Remove(name string) (ok bool) {
	c, ok := s.index.findByName(name)
	if !ok {
		return false
	}

	s.remove(c)

	return true
}

// remove c from the indexes.
func (s *Storage) remove(c *Persistent) {
	if err := c.CloseUpstreams(); err != nil {
		log.Error("client container: removing client %s: %s", c.Name, err)
	}

	s.index.Delete(c)
}

// Update updates a persistent client by its name.
func (s *Storage) Update(prev, c *Persistent) (err error) {
	if prev.Name != c.Name {
		_, ok := s.index.findByName(c.Name)
		if ok {
			return errors.Error("client already exists")
		}
	}

	if c.EqualIDs(prev) {
		s.remove(prev)
		s.add(c)

		return nil
	}

	err = s.index.Clashes(c)
	if err != nil {
		// Don't wrap the error since it's informative enough as is.
		return err
	}

	s.remove(prev)
	s.add(c)

	return nil
}

// RuntimeClient returns the saved runtime client by ip.  If no such client
// exists, returns nil.
func (s *Storage) RuntimeClient(ip netip.Addr) (rc *Runtime, ok bool) {
	rc = s.runtimeIndex[ip]
	if rc != nil {
		return rc, true
	}

	return nil, false
}

// RuntimeClientStore saves the runtime client by ip.
func (s *Storage) RuntimeClientStore(ip netip.Addr, rc *Runtime) {
	s.runtimeIndex[ip] = rc
}

// RuntimeClientSize returns the number of the runtime clients.
func (s *Storage) RuntimeClientSize() (n int) {
	return len(s.runtimeIndex)
}

// RuntimeClientRange calls cb for each runtime client.
func (s *Storage) RuntimeClientRange(cb func(ip netip.Addr, rc *Runtime) (cont bool)) {
	for ip, rc := range s.runtimeIndex {
		if !cb(ip, rc) {
			return
		}
	}
}

// RuntimeClientDelete removes the runtime client by ip.
func (s *Storage) RuntimeClientDelete(ip netip.Addr) {
	delete(s.runtimeIndex, ip)
}

// Range calls cb for each persistent client.
func (s *Storage) Range(cb func(c *Persistent) (cont bool)) {
	s.index.Range(cb)
}
