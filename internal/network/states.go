package network

import "sync"

type states struct {
	mu         sync.RWMutex
	clientID   string
	algoID     string
	macAddress string
	ticket     string
	userIP     string
	acIP       string
	isRunning  bool
	isLogged   bool
	schoolID   string
	domain     string
	area       string
	ticketURL  string
	authURL    string
	extraCfg   map[string]string
}

var States = &states{
	isRunning: true,
	extraCfg:  make(map[string]string),
}

func (s *states) GetClientID() string   { s.mu.RLock(); defer s.mu.RUnlock(); return s.clientID }
func (s *states) SetClientID(v string)  { s.mu.Lock(); defer s.mu.Unlock(); s.clientID = v }
func (s *states) GetAlgoID() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.algoID }
func (s *states) SetAlgoID(v string)    { s.mu.Lock(); defer s.mu.Unlock(); s.algoID = v }
func (s *states) GetMacAddress() string { s.mu.RLock(); defer s.mu.RUnlock(); return s.macAddress }
func (s *states) SetMacAddress(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.macAddress = v }
func (s *states) GetTicket() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.ticket }
func (s *states) SetTicket(v string)    { s.mu.Lock(); defer s.mu.Unlock(); s.ticket = v }
func (s *states) GetUserIP() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.userIP }
func (s *states) SetUserIP(v string)    { s.mu.Lock(); defer s.mu.Unlock(); s.userIP = v }
func (s *states) GetAcIP() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.acIP }
func (s *states) SetAcIP(v string)      { s.mu.Lock(); defer s.mu.Unlock(); s.acIP = v }
func (s *states) IsRunning() bool       { s.mu.RLock(); defer s.mu.RUnlock(); return s.isRunning }
func (s *states) SetRunning(v bool)     { s.mu.Lock(); defer s.mu.Unlock(); s.isRunning = v }
func (s *states) IsLogged() bool        { s.mu.RLock(); defer s.mu.RUnlock(); return s.isLogged }
func (s *states) SetLogged(v bool)      { s.mu.Lock(); defer s.mu.Unlock(); s.isLogged = v }
func (s *states) GetSchoolID() string   { s.mu.RLock(); defer s.mu.RUnlock(); return s.schoolID }
func (s *states) SetSchoolID(v string)  { s.mu.Lock(); defer s.mu.Unlock(); s.schoolID = v }
func (s *states) GetDomain() string     { s.mu.RLock(); defer s.mu.RUnlock(); return s.domain }
func (s *states) SetDomain(v string)    { s.mu.Lock(); defer s.mu.Unlock(); s.domain = v }
func (s *states) GetArea() string       { s.mu.RLock(); defer s.mu.RUnlock(); return s.area }
func (s *states) SetArea(v string)      { s.mu.Lock(); defer s.mu.Unlock(); s.area = v }
func (s *states) GetTicketURL() string  { s.mu.RLock(); defer s.mu.RUnlock(); return s.ticketURL }
func (s *states) SetTicketURL(v string) { s.mu.Lock(); defer s.mu.Unlock(); s.ticketURL = v }
func (s *states) GetAuthURL() string    { s.mu.RLock(); defer s.mu.RUnlock(); return s.authURL }
func (s *states) SetAuthURL(v string)   { s.mu.Lock(); defer s.mu.Unlock(); s.authURL = v }
func (s *states) GetExtraCfgURL() map[string]string { return s.extraCfg }

func (s *states) RefreshStates() {
	uuid := newUUID()
	s.clientID = uuid
	s.algoID = "00000000-0000-0000-0000-000000000000"
	s.macAddress = randomMAC()
}

func (s *states) GetExtraHeaders() map[string]string {
	h := make(map[string]string)
	if s.schoolID != "" {
		h["CDC-SchoolId"] = s.schoolID
	}
	return h
}
