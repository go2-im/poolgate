package webauthnsvc

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/go2-im/poolgate/internal/model"
	"github.com/go2-im/poolgate/internal/store"
)

// fakeStore is an in-memory Store for the User adapter tests and the ceremony
// tests. It supports the full Stage-3 Store surface.
type fakeStore struct {
	creds []model.WebAuthnCredential
	err   error

	insertErr error
	getErr    error
	updateErr error
	countErr  error

	inserted []model.WebAuthnCredential
	updates  map[string]uint32
	nextID   int
}

func (f *fakeStore) ListWebAuthnCredentials(context.Context) ([]model.WebAuthnCredential, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.creds, nil
}

func (f *fakeStore) CountWebAuthnCredentials(context.Context) (int, error) {
	if f.countErr != nil {
		return 0, f.countErr
	}
	return len(f.creds), nil
}

func (f *fakeStore) InsertWebAuthnCredential(_ context.Context, c model.WebAuthnCredential) (model.WebAuthnCredential, error) {
	if f.insertErr != nil {
		return model.WebAuthnCredential{}, f.insertErr
	}
	if c.ID == "" {
		f.nextID++
		c.ID = fmt.Sprintf("wac_%d", f.nextID)
	}
	f.creds = append(f.creds, c)
	f.inserted = append(f.inserted, c)
	return c, nil
}

func (f *fakeStore) GetWebAuthnCredentialByCredID(_ context.Context, credID []byte) (model.WebAuthnCredential, error) {
	if f.getErr != nil {
		return model.WebAuthnCredential{}, f.getErr
	}
	for _, c := range f.creds {
		if bytes.Equal(c.CredID, credID) {
			return c, nil
		}
	}
	return model.WebAuthnCredential{}, store.ErrNotFound
}

func (f *fakeStore) UpdateWebAuthnSignCount(_ context.Context, id string, signCount uint32) error {
	if f.updateErr != nil {
		return f.updateErr
	}
	if f.updates == nil {
		f.updates = map[string]uint32{}
	}
	f.updates[id] = signCount
	for i := range f.creds {
		if f.creds[i].ID == id {
			f.creds[i].SignCount = signCount
		}
	}
	return nil
}

func adminCfg(admin model.ListenConfig) model.Config {
	return model.Config{Server: model.ServerConfig{Admin: admin}}
}

// ---- RP resolution --------------------------------------------------------

func TestResolveRP(t *testing.T) {
	tests := []struct {
		name        string
		admin       model.ListenConfig
		wantRPID    string
		wantOrigins []string
		wantErr     bool
	}{
		{
			name:        "explicit external_origin and rp_id",
			admin:       model.ListenConfig{ExternalOrigin: "https://admin.example.com", RPID: "example.com"},
			wantRPID:    "example.com",
			wantOrigins: []string{"https://admin.example.com"},
		},
		{
			name:        "rp_id derived from external_origin host",
			admin:       model.ListenConfig{ExternalOrigin: "https://admin.example.com:8443"},
			wantRPID:    "admin.example.com",
			wantOrigins: []string{"https://admin.example.com:8443"},
		},
		{
			name:        "derived loopback origin maps IP to localhost (browsers reject IP RP IDs)",
			admin:       model.ListenConfig{Host: "127.0.0.1", Port: 7070},
			wantRPID:    "localhost",
			wantOrigins: []string{"http://localhost:7070"},
		},
		{
			name:        "empty host and port default to localhost:7070",
			admin:       model.ListenConfig{},
			wantRPID:    "localhost",
			wantOrigins: []string{"http://localhost:7070"},
		},
		{
			name:        "explicit non-loopback host is preserved (operator must set a real domain)",
			admin:       model.ListenConfig{Host: "192.168.1.5", Port: 7070},
			wantRPID:    "192.168.1.5",
			wantOrigins: []string{"http://192.168.1.5:7070"},
		},
		{
			name:    "origin without scheme is rejected",
			admin:   model.ListenConfig{ExternalOrigin: "admin.example.com"},
			wantErr: true,
		},
		{
			name:    "unparseable origin is rejected",
			admin:   model.ListenConfig{ExternalOrigin: "http://[::1"},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rpID, origins, err := resolveRP(tt.admin)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveRP(%+v) = nil error, want error", tt.admin)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveRP: %v", err)
			}
			if rpID != tt.wantRPID {
				t.Errorf("rpID = %q, want %q", rpID, tt.wantRPID)
			}
			if len(origins) != len(tt.wantOrigins) || origins[0] != tt.wantOrigins[0] {
				t.Errorf("origins = %v, want %v", origins, tt.wantOrigins)
			}
		})
	}
}

// ---- New ------------------------------------------------------------------

func TestNew(t *testing.T) {
	if _, err := New(adminCfg(model.ListenConfig{}), nil); err == nil {
		t.Fatal("New(nil store) = nil error, want error")
	}

	if _, err := New(adminCfg(model.ListenConfig{ExternalOrigin: "nope"}), &fakeStore{}); err == nil {
		t.Fatal("New(bad origin) = nil error, want error")
	}

	svc, err := New(adminCfg(model.ListenConfig{ExternalOrigin: "https://admin.example.com", RPID: "example.com"}), &fakeStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.RPID() != "example.com" {
		t.Errorf("RPID() = %q, want example.com", svc.RPID())
	}
	if got := svc.RPOrigins(); len(got) != 1 || got[0] != "https://admin.example.com" {
		t.Errorf("RPOrigins() = %v", got)
	}
	if svc.WebAuthn() == nil {
		t.Error("WebAuthn() = nil")
	}
	if svc.Challenges() == nil {
		t.Error("Challenges() = nil")
	}
}

func TestNewChallengeTTLOption(t *testing.T) {
	svc, err := New(adminCfg(model.ListenConfig{}), &fakeStore{}, WithChallengeTTL(time.Second))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if svc.challengeTTL != time.Second {
		t.Errorf("challengeTTL = %v, want 1s", svc.challengeTTL)
	}
}

func TestNewClockAndRandOptions(t *testing.T) {
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0).UTC()}
	seed := bytes.Repeat([]byte{0x11}, 64)
	svc, err := New(adminCfg(model.ListenConfig{}), &fakeStore{},
		WithClock(clk.now), WithRand(bytes.NewReader(seed)), WithChallengeTTL(time.Minute))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The injected clock reaches the challenge store: an entry put now expires
	// exactly one TTL later.
	id, err := svc.Challenges().Put(&webauthn.SessionData{Challenge: "c"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	clk.add(time.Minute)
	if _, err := svc.Challenges().Take(id); !errors.Is(err, ErrChallengeNotFound) {
		t.Errorf("Take after TTL err = %v, want ErrChallengeNotFound", err)
	}

	// nil options are ignored (defaults preserved).
	if _, err := New(adminCfg(model.ListenConfig{}), &fakeStore{},
		WithClock(nil), WithRand(nil), WithChallengeTTL(0)); err != nil {
		t.Fatalf("New with nil options: %v", err)
	}
}

// ---- operator user --------------------------------------------------------

func TestOperatorUser(t *testing.T) {
	stored := []model.WebAuthnCredential{
		{CredID: []byte{1, 2, 3}, PublicKey: []byte{9}, SignCount: 7, AAGUID: []byte{0xaa}, Transports: []string{"hybrid", "internal"}},
		{CredID: []byte{4, 5}, PublicKey: []byte{8}, Transports: []string{}},
	}
	svc, err := New(adminCfg(model.ListenConfig{}), &fakeStore{creds: stored})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	u, err := svc.OperatorUser(context.Background())
	if err != nil {
		t.Fatalf("OperatorUser: %v", err)
	}
	if u.WebAuthnName() != operatorName || u.WebAuthnDisplayName() != operatorDisplayName {
		t.Errorf("name/display = %q/%q", u.WebAuthnName(), u.WebAuthnDisplayName())
	}
	if len(u.WebAuthnID()) != 32 {
		t.Errorf("WebAuthnID len = %d, want 32", len(u.WebAuthnID()))
	}
	// ID is stable across calls.
	svc2, _ := New(adminCfg(model.ListenConfig{}), &fakeStore{})
	u2, _ := svc2.OperatorUser(context.Background())
	if string(u.WebAuthnID()) != string(u2.WebAuthnID()) {
		t.Error("WebAuthnID not stable across services")
	}
	creds := u.WebAuthnCredentials()
	if len(creds) != 2 {
		t.Fatalf("WebAuthnCredentials len = %d, want 2", len(creds))
	}
	if string(creds[0].ID) != string([]byte{1, 2, 3}) || creds[0].Authenticator.SignCount != 7 {
		t.Errorf("cred0 mismatch: %+v", creds[0])
	}
}

func TestOperatorUserStoreError(t *testing.T) {
	svc, err := New(adminCfg(model.ListenConfig{}), &fakeStore{err: errors.New("boom")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := svc.OperatorUser(context.Background()); err == nil {
		t.Fatal("OperatorUser with store error = nil, want error")
	}
}

// ---- credential round-trip ------------------------------------------------

func TestCredentialRoundTrip(t *testing.T) {
	orig := webauthn.Credential{
		ID:        []byte{0x01, 0x02, 0x03, 0x04},
		PublicKey: []byte{0x0a, 0x0b, 0x0c},
		Transport: []protocol.AuthenticatorTransport{protocol.Hybrid, protocol.Internal, protocol.USB},
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte{0xde, 0xad, 0xbe, 0xef},
			SignCount: 42,
		},
	}
	m := credentialToModel(orig)
	if string(m.CredID) != string(orig.ID) || string(m.PublicKey) != string(orig.PublicKey) {
		t.Fatalf("model bytes mismatch: %+v", m)
	}
	if m.SignCount != 42 || string(m.AAGUID) != string(orig.Authenticator.AAGUID) {
		t.Fatalf("model auth mismatch: %+v", m)
	}
	if len(m.Transports) != 3 || m.Transports[0] != "hybrid" || m.Transports[2] != "usb" {
		t.Fatalf("model transports mismatch: %v", m.Transports)
	}

	back := credentialFromModel(m)
	if string(back.ID) != string(orig.ID) || string(back.PublicKey) != string(orig.PublicKey) {
		t.Fatalf("roundtrip bytes mismatch: %+v", back)
	}
	if back.Authenticator.SignCount != orig.Authenticator.SignCount {
		t.Fatalf("roundtrip sign count = %d", back.Authenticator.SignCount)
	}
	if string(back.Authenticator.AAGUID) != string(orig.Authenticator.AAGUID) {
		t.Fatalf("roundtrip aaguid mismatch")
	}
	if len(back.Transport) != 3 || back.Transport[1] != protocol.Internal {
		t.Fatalf("roundtrip transports mismatch: %v", back.Transport)
	}
}

func TestCredentialFromModelEmptyTransports(t *testing.T) {
	back := credentialFromModel(model.WebAuthnCredential{CredID: []byte{1}, PublicKey: []byte{2}})
	if len(back.Transport) != 0 {
		t.Errorf("Transport = %v, want empty", back.Transport)
	}
}

// ---- options builder ------------------------------------------------------

func TestRegistrationOptionsShape(t *testing.T) {
	svc, err := New(adminCfg(model.ListenConfig{}), &fakeStore{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	opts := svc.RegistrationOptions()
	if len(opts) != 2 {
		t.Fatalf("RegistrationOptions len = %d, want 2", len(opts))
	}
	// Apply the options to a creation-options struct and assert the selection
	// policy: no attachment filter (platform + cross-platform + hybrid all
	// eligible), discoverable credentials preferred, UV preferred, none attest.
	cco := &protocol.PublicKeyCredentialCreationOptions{}
	for _, opt := range opts {
		opt(cco)
	}
	sel := cco.AuthenticatorSelection
	if sel.AuthenticatorAttachment != "" {
		t.Errorf("AuthenticatorAttachment = %q, want empty (any authenticator)", sel.AuthenticatorAttachment)
	}
	if sel.ResidentKey != protocol.ResidentKeyRequirementPreferred {
		t.Errorf("ResidentKey = %q, want preferred", sel.ResidentKey)
	}
	if sel.UserVerification != protocol.VerificationPreferred {
		t.Errorf("UserVerification = %q, want preferred", sel.UserVerification)
	}
	if cco.Attestation != protocol.PreferNoAttestation {
		t.Errorf("Attestation = %q, want none", cco.Attestation)
	}
}
