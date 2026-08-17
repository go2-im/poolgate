package admin

import (
	"context"
	"errors"
	"strconv"
	"sync"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/go2-im/poolgate/internal/adminauth"
	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
	"github.com/go2-im/poolgate/internal/webauthnsvc"
)

// ---- fake session manager -------------------------------------------------

// fakeSessions is an in-memory SessionManager. CSRF tokens are the fixed string
// "csrf-<sessionID>" so tests can forge a valid header deterministically.
type fakeSessions struct {
	mu           sync.Mutex
	sessions     map[string]model.Session
	seq          int
	recoveryOK   map[string]bool // codes that verify
	failCreate   bool
	failCSRF     bool
	failRecovery bool // return a non-sentinel error from VerifyRecoveryCode
	failGenCodes bool
	genCodes     []string
}

func newFakeSessions() *fakeSessions {
	return &fakeSessions{
		sessions:   map[string]model.Session{},
		recoveryOK: map[string]bool{},
		genCodes:   []string{"code-a", "code-b"},
	}
}

func (f *fakeSessions) put() model.Session {
	f.seq++
	id := "sess-" + itoa(f.seq)
	s := model.Session{ID: id}
	f.sessions[id] = s
	return s
}

func (f *fakeSessions) CreateSession(context.Context) (model.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCreate {
		return model.Session{}, errors.New("create failed")
	}
	return f.put(), nil
}

func (f *fakeSessions) ValidateSession(_ context.Context, id string) (model.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.sessions[id]
	if !ok {
		return model.Session{}, adminauth.ErrSessionNotFound
	}
	return s, nil
}

func (f *fakeSessions) RotateSession(_ context.Context, oldID string) (model.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failCreate {
		return model.Session{}, errors.New("rotate failed")
	}
	delete(f.sessions, oldID)
	return f.put(), nil
}

func (f *fakeSessions) RevokeSession(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, id)
	return nil
}

func (f *fakeSessions) RevokeAllSessions(context.Context) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := int64(len(f.sessions))
	f.sessions = map[string]model.Session{}
	return n, nil
}

func (f *fakeSessions) IssueCSRF(sessionID string) (string, error) {
	if f.failCSRF {
		return "", errors.New("csrf failed")
	}
	return "csrf-" + sessionID, nil
}

func (f *fakeSessions) VerifyCSRF(sessionID, token string) bool {
	return token == "csrf-"+sessionID
}

func (f *fakeSessions) VerifyRecoveryCode(_ context.Context, code string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failRecovery {
		return errors.New("recovery backend down")
	}
	if f.recoveryOK[code] {
		return nil
	}
	return adminauth.ErrRecoveryCodeInvalid
}

func (f *fakeSessions) GenerateRecoveryCodes(_ context.Context, _ int) ([]string, error) {
	if f.failGenCodes {
		return nil, errors.New("gen failed")
	}
	return f.genCodes, nil
}

// ---- fake ceremonies ------------------------------------------------------

// fakeUser is a minimal webauthn.User returned by a successful login.
type fakeUser struct{}

func (fakeUser) WebAuthnID() []byte                         { return []byte("op") }
func (fakeUser) WebAuthnName() string                       { return "operator" }
func (fakeUser) WebAuthnDisplayName() string                { return "operator" }
func (fakeUser) WebAuthnCredentials() []webauthn.Credential { return nil }

// fakeCeremonies is a scriptable Ceremonies implementation.
type fakeCeremonies struct {
	beginRegErr    error
	finishRegErr   error
	beginLoginErr  error
	finishLoginErr error
	lastGate       webauthnsvc.RegisterGate
	rpID           string
}

func (f *fakeCeremonies) BeginRegistration(_ context.Context, gate webauthnsvc.RegisterGate) (*protocol.CredentialCreation, string, error) {
	f.lastGate = gate
	if f.beginRegErr != nil {
		return nil, "", f.beginRegErr
	}
	return &protocol.CredentialCreation{}, "chal-reg", nil
}

func (f *fakeCeremonies) FinishRegistration(_ context.Context, gate webauthnsvc.RegisterGate, _ string, _ []byte) (model.WebAuthnCredential, bool, error) {
	f.lastGate = gate
	if f.finishRegErr != nil {
		return model.WebAuthnCredential{}, false, f.finishRegErr
	}
	// Simulate the ceremony's first-passkey determination: a bootstrap token means
	// the bootstrap (first) ceremony.
	return model.WebAuthnCredential{ID: "cred-1"}, gate.BootstrapToken != "", nil
}

func (f *fakeCeremonies) BeginLogin(context.Context) (*protocol.CredentialAssertion, string, error) {
	if f.beginLoginErr != nil {
		return nil, "", f.beginLoginErr
	}
	return &protocol.CredentialAssertion{}, "chal-login", nil
}

func (f *fakeCeremonies) FinishLogin(context.Context, string, []byte) (webauthn.User, error) {
	if f.finishLoginErr != nil {
		return nil, f.finishLoginErr
	}
	return fakeUser{}, nil
}

func (f *fakeCeremonies) RPID() string {
	if f.rpID == "" {
		return "localhost"
	}
	return f.rpID
}

// ---- fake store -----------------------------------------------------------

// fakeStore is an in-memory Store. It is intentionally simple; the real SQL
// behavior is covered by internal/store's own tests.
type fakeStore struct {
	mu       sync.Mutex
	accounts map[string]model.Account
	keys     map[string]model.ApiKey
	eps      map[string]model.Endpoint
	groups   map[string]model.PolicyGroup
	usage    map[string]model.UsageSnapshot
	checks   map[string][]model.HealthCheck
	channels map[string]model.NotifyChannel
	reqLogs  []model.RequestLog
	audit    []model.AuditEntry
	seq      int
	failList bool // force list operations to error
	// auditBrokenAt, when set, makes VerifyAuditChain report a broken chain at
	// that entry id (empty = intact).
	auditBrokenAt string
}

// VerifyAuditChain reports the in-memory audit count and, when auditBrokenAt is
// set, a broken chain at that id (test scaffolding for the verify endpoint).
func (f *fakeStore) VerifyAuditChain(_ context.Context) (bool, int, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return false, 0, "", errors.New("verify failed")
	}
	if f.auditBrokenAt != "" {
		return false, len(f.audit), f.auditBrokenAt, nil
	}
	return true, len(f.audit), "", nil
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		accounts: map[string]model.Account{},
		keys:     map[string]model.ApiKey{},
		eps:      map[string]model.Endpoint{},
		groups:   map[string]model.PolicyGroup{},
		usage:    map[string]model.UsageSnapshot{},
		checks:   map[string][]model.HealthCheck{},
		channels: map[string]model.NotifyChannel{},
	}
}

func (f *fakeStore) id(prefix string) string {
	f.seq++
	return prefix + "-" + itoa(f.seq)
}

func (f *fakeStore) InsertAccount(_ context.Context, a model.Account) (model.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.ID == "" {
		a.ID = f.id("acct")
	}
	f.accounts[a.ID] = a
	return a, nil
}

func (f *fakeStore) InsertAccountUnique(_ context.Context, a model.Account) (model.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if a.AccountID != "" {
		for _, existing := range f.accounts {
			if existing.AccountID == a.AccountID {
				return model.Account{}, store.ErrAlreadyExists
			}
		}
	}
	if a.ID == "" {
		a.ID = f.id("acct")
	}
	f.accounts[a.ID] = a
	return a, nil
}

func (f *fakeStore) GetAccount(_ context.Context, id string) (model.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[id]
	if !ok {
		return model.Account{}, store.ErrNotFound
	}
	return a, nil
}

func (f *fakeStore) ListAccounts(context.Context) ([]model.Account, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	out := make([]model.Account, 0, len(f.accounts))
	for _, a := range f.accounts {
		out = append(out, a)
	}
	return out, nil
}

func (f *fakeStore) DeleteAccount(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.accounts[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.accounts, id)
	return nil
}

func (f *fakeStore) UpdateAccountMeta(_ context.Context, id, label string, cap int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a, ok := f.accounts[id]
	if !ok {
		return store.ErrNotFound
	}
	a.Label = label
	a.ConcurrencyCap = cap
	f.accounts[id] = a
	return nil
}

func (f *fakeStore) InsertApiKey(_ context.Context, k model.ApiKey) (model.ApiKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if k.ID == "" {
		k.ID = f.id("key")
	}
	f.keys[k.ID] = k
	return k, nil
}

func (f *fakeStore) ListApiKeys(context.Context) ([]model.ApiKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	out := make([]model.ApiKey, 0, len(f.keys))
	for _, k := range f.keys {
		out = append(out, k)
	}
	return out, nil
}

func (f *fakeStore) GetApiKeyByID(_ context.Context, id string) (model.ApiKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok {
		return model.ApiKey{}, store.ErrNotFound
	}
	return k, nil
}

func (f *fakeStore) DeleteApiKey(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.keys[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.keys, id)
	return nil
}

func (f *fakeStore) RotateApiKey(_ context.Context, id, newKey string) (model.ApiKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k, ok := f.keys[id]
	if !ok {
		return model.ApiKey{}, store.ErrNotFound
	}
	k.Key = newKey
	f.keys[id] = k
	return k, nil
}

func (f *fakeStore) InsertAuditEntry(_ context.Context, e model.AuditEntry) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if e.ID == "" {
		f.seq++
		e.ID = "audit_" + strconv.Itoa(f.seq)
	}
	f.audit = append(f.audit, e)
	return nil
}

func (f *fakeStore) ListAuditEntries(_ context.Context, limit, offset int) ([]model.AuditEntry, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	// newest-first
	rev := make([]model.AuditEntry, 0, len(f.audit))
	for i := len(f.audit) - 1; i >= 0; i-- {
		rev = append(rev, f.audit[i])
	}
	if limit <= 0 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	if offset >= len(rev) {
		return []model.AuditEntry{}, nil
	}
	end := offset + limit
	if end > len(rev) {
		end = len(rev)
	}
	return rev[offset:end], nil
}

func (f *fakeStore) InsertEndpoint(_ context.Context, e model.Endpoint) (model.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.eps[e.Name]; dup {
		return model.Endpoint{}, errors.New("duplicate endpoint")
	}
	if _, ok := f.groups[e.GroupID]; !ok {
		return model.Endpoint{}, errors.New("unknown group")
	}
	f.eps[e.Name] = e
	return e, nil
}

func (f *fakeStore) GetEndpoint(_ context.Context, name string) (model.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	e, ok := f.eps[name]
	if !ok {
		return model.Endpoint{}, store.ErrNotFound
	}
	return e, nil
}

func (f *fakeStore) ListEndpoints(context.Context) ([]model.Endpoint, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	out := make([]model.Endpoint, 0, len(f.eps))
	for _, e := range f.eps {
		out = append(out, e)
	}
	return out, nil
}

func (f *fakeStore) DeleteEndpoint(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.eps[name]; !ok {
		return store.ErrNotFound
	}
	delete(f.eps, name)
	return nil
}

func (f *fakeStore) InsertPolicyGroup(_ context.Context, g model.PolicyGroup) (model.PolicyGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if g.ID == "" {
		g.ID = f.id("grp")
	}
	for _, existing := range f.groups {
		if existing.Name == g.Name {
			return model.PolicyGroup{}, errors.New("duplicate name")
		}
	}
	f.groups[g.ID] = g
	return g, nil
}

func (f *fakeStore) GetPolicyGroup(_ context.Context, id string) (model.PolicyGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g, ok := f.groups[id]
	if !ok {
		return model.PolicyGroup{}, store.ErrNotFound
	}
	return g, nil
}

func (f *fakeStore) ListPolicyGroups(context.Context) ([]model.PolicyGroup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	out := make([]model.PolicyGroup, 0, len(f.groups))
	for _, g := range f.groups {
		out = append(out, g)
	}
	return out, nil
}

func (f *fakeStore) UpdatePolicyGroup(_ context.Context, g model.PolicyGroup) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.groups[g.ID]; !ok {
		return store.ErrNotFound
	}
	f.groups[g.ID] = g
	return nil
}

func (f *fakeStore) DeletePolicyGroup(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.groups[id]; !ok {
		return store.ErrNotFound
	}
	// Refuse when an endpoint still references the group (FK RESTRICT parity).
	for _, e := range f.eps {
		if e.GroupID == id {
			return errors.New("referenced by endpoint")
		}
	}
	delete(f.groups, id)
	return nil
}

func (f *fakeStore) GetLatestUsage(_ context.Context, accountID string) (model.UsageSnapshot, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	snap, ok := f.usage[accountID]
	if !ok {
		return model.UsageSnapshot{}, store.ErrNotFound
	}
	return snap, nil
}

func (f *fakeStore) ListHealthChecks(_ context.Context, accountID string, _ int) ([]model.HealthCheck, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.checks[accountID], nil
}

func (f *fakeStore) SchemaVersion(context.Context) (int, error) { return 3, nil }

// itoa is a tiny base-10 int formatter to avoid importing strconv in the fakes.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// ---- failing wrappers for internal-error (500) branch coverage ------------
//
// Each embeds a working implementation and overrides exactly one method to
// return an error, so a single collaborator failure can be exercised in
// isolation.

func errNotAuthorizedForTest() error { return webauthnsvc.ErrNotAuthorized }

type failingRevoke struct{ SessionManager }

func (failingRevoke) RevokeSession(context.Context, string) error {
	return errors.New("revoke failed")
}

type failingRevokeAll struct{ SessionManager }

func (failingRevokeAll) RevokeAllSessions(context.Context) (int64, error) {
	return 0, errors.New("revoke-all failed")
}

type failingInsertAccount struct{ Store }

func (failingInsertAccount) InsertAccount(context.Context, model.Account) (model.Account, error) {
	return model.Account{}, errors.New("insert failed")
}

func (failingInsertAccount) InsertAccountUnique(context.Context, model.Account) (model.Account, error) {
	return model.Account{}, errors.New("insert failed")
}

type failingInsertKey struct{ Store }

func (failingInsertKey) InsertApiKey(context.Context, model.ApiKey) (model.ApiKey, error) {
	return model.ApiKey{}, errors.New("insert failed")
}

type failingUpdateGroup struct{ Store }

func (failingUpdateGroup) UpdatePolicyGroup(context.Context, model.PolicyGroup) error {
	return errors.New("update failed")
}

type failingUsageRead struct{ Store }

func (failingUsageRead) GetLatestUsage(context.Context, string) (model.UsageSnapshot, error) {
	return model.UsageSnapshot{}, errors.New("usage read failed")
}

type failingHealthRead struct{ Store }

func (failingHealthRead) ListHealthChecks(context.Context, string, int) ([]model.HealthCheck, error) {
	return nil, errors.New("health read failed")
}

// ---- fake notify channels -------------------------------------------------

func (f *fakeStore) InsertNotifyChannel(_ context.Context, ch model.NotifyChannel) (model.NotifyChannel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if ch.ID == "" {
		ch.ID = f.id("ntf")
	}
	f.channels[ch.ID] = ch
	return ch, nil
}

func (f *fakeStore) GetNotifyChannel(_ context.Context, id string) (model.NotifyChannel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ch, ok := f.channels[id]
	if !ok {
		return model.NotifyChannel{}, store.ErrNotFound
	}
	return ch, nil
}

func (f *fakeStore) ListNotifyChannels(context.Context) ([]model.NotifyChannel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	out := make([]model.NotifyChannel, 0, len(f.channels))
	for _, ch := range f.channels {
		out = append(out, ch)
	}
	return out, nil
}

func (f *fakeStore) UpdateNotifyChannel(_ context.Context, ch model.NotifyChannel) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.channels[ch.ID]; !ok {
		return store.ErrNotFound
	}
	f.channels[ch.ID] = ch
	return nil
}

func (f *fakeStore) DeleteNotifyChannel(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.channels[id]; !ok {
		return store.ErrNotFound
	}
	delete(f.channels, id)
	return nil
}

// ---- fake request logs (monitor) -----------------------------------------

func (f *fakeStore) ListRequestLogs(_ context.Context, filter model.RequestLogFilter, limit, offset int) ([]model.RequestLog, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return nil, errors.New("list failed")
	}
	var out []model.RequestLog
	for _, l := range f.reqLogs {
		if filter.Matches(l) {
			out = append(out, l)
		}
	}
	if offset > 0 {
		if offset >= len(out) {
			return nil, nil
		}
		out = out[offset:]
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (f *fakeStore) CountRequestLogs(_ context.Context, filter model.RequestLogFilter) (store.RequestCounters, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList {
		return store.RequestCounters{}, errors.New("count failed")
	}
	var c store.RequestCounters
	for _, l := range f.reqLogs {
		if !filter.Matches(l) {
			continue
		}
		c.Total++
		if l.Status >= 200 && l.Status < 300 {
			c.Success++
		}
		c.TokensIn += l.TokensIn
		c.TokensOut += l.TokensOut
	}
	c.Error = c.Total - c.Success
	return c, nil
}

// fakeMonitor is an in-memory MonitorStream: Subscribe returns a channel the test
// feeds via push().
type fakeMonitor struct {
	mu   sync.Mutex
	subs []chan model.RequestLog
}

func (m *fakeMonitor) Subscribe(_ model.RequestLogFilter) (<-chan model.RequestLog, func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	ch := make(chan model.RequestLog, 8)
	m.subs = append(m.subs, ch)
	return ch, func() {}
}

func (m *fakeMonitor) push(l model.RequestLog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ch := range m.subs {
		select {
		case ch <- l:
		default:
		}
	}
}
