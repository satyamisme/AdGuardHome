package client

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/log"
	"golang.org/x/exp/maps"
)

// Storage stores information about runtime and persistent clients.
type Storage struct {
	// list maps persistent client name to client information.
	list map[string]*Persistent

	// index stores all information about persistent clients.
	index *Index
}

// NewStorage returns initialized client storage.
func NewStorage() (s *Storage) {
	return &Storage{
		list:  map[string]*Persistent{},
		index: NewIndex(),
	}
}

// List returns a list of persistent clients.
func (s *Storage) List() (cs []*Persistent) {
	return maps.Values(s.list)
}

// Size returns the size of the persistent client list.
func (s *Storage) Size() (n int) {
	return len(s.list)
}

// Find finds persistent client by string representation of the client ID, IP
// address, or MAC.
func (s *Storage) Find(id string) (c *Persistent, ok bool) {
	return s.index.Find(id)
}

// FindByName finds a persistent client by name.
func (s *Storage) FindByName(name string) (c *Persistent, ok bool) {
	c, ok = s.list[name]

	return c, ok
}

// Add adds a new persistent client.  ok is false if such client already exists
// or if an error occurred.
func (s *Storage) Add(c *Persistent) (ok bool, err error) {
	_, ok = s.list[c.Name]
	if ok {
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
	s.list[c.Name] = c
	s.index.Add(c)
}

// Remove removes a persistent client.  ok is false if there is no such client.
func (s *Storage) Remove(name string) (ok bool) {
	c, ok := s.list[name]
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

	delete(s.list, c.Name)
	s.index.Delete(c)
}

// Update updates a persistent client by its name.
func (s *Storage) Update(prev, c *Persistent) (err error) {
	if prev.Name != c.Name {
		_, ok := s.list[c.Name]
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
