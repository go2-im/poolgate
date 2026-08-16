package webauthnsvc

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/go2-im/poolgate/internal/model"
)

// ---- software authenticator ----------------------------------------------

// softwareAuthenticator is a minimal in-process WebAuthn authenticator (ES256 /
// P-256, "none" attestation) used to drive full begin->finish register and
// begin->finish login ceremonies deterministically. It mirrors just enough of the
// CTAP2/WebAuthn wire format for go-webauthn's verifier to accept it.
type softwareAuthenticator struct {
	rpID    string
	origin  string
	credID  []byte
	priv    *ecdsa.PrivateKey
	signCnt uint32
}

func newSoftwareAuthenticator(t *testing.T, rpID, origin string) *softwareAuthenticator {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	credID := make([]byte, 16)
	if _, err := rand.Read(credID); err != nil {
		t.Fatalf("cred id: %v", err)
	}
	return &softwareAuthenticator{rpID: rpID, origin: origin, credID: credID, priv: priv}
}

// coseKey encodes the P-256 public key as a COSE_Key (ES256) CBOR map.
func (a *softwareAuthenticator) coseKey(t *testing.T) []byte {
	t.Helper()
	x := a.priv.PublicKey.X.FillBytes(make([]byte, 32))
	y := a.priv.PublicKey.Y.FillBytes(make([]byte, 32))
	m := map[int]interface{}{
		1:  2,  // kty: EC2
		3:  -7, // alg: ES256
		-1: 1,  // crv: P-256
		-2: x,  // x-coordinate
		-3: y,  // y-coordinate
	}
	b, err := cbor.Marshal(m)
	if err != nil {
		t.Fatalf("cbor cose key: %v", err)
	}
	return b
}

// authData builds authenticatorData; when attested it appends the attested
// credential data (aaguid + credential id + COSE public key) and sets the AT flag.
func (a *softwareAuthenticator) authData(t *testing.T, attested bool) []byte {
	t.Helper()
	rpIDHash := sha256.Sum256([]byte(a.rpID))
	var buf bytes.Buffer
	buf.Write(rpIDHash[:])
	flags := byte(0x01 | 0x04) // UP | UV
	if attested {
		flags |= 0x40 // AT
	}
	buf.WriteByte(flags)
	cnt := make([]byte, 4)
	binary.BigEndian.PutUint32(cnt, a.signCnt)
	buf.Write(cnt)
	if attested {
		buf.Write(make([]byte, 16)) // zero AAGUID
		credLen := make([]byte, 2)
		binary.BigEndian.PutUint16(credLen, uint16(len(a.credID)))
		buf.Write(credLen)
		buf.Write(a.credID)
		buf.Write(a.coseKey(t))
	}
	return buf.Bytes()
}

// register produces a registration (attestation) response body for the given
// base64url challenge.
func (a *softwareAuthenticator) register(t *testing.T, challenge string) []byte {
	t.Helper()
	cdj := a.clientDataJSON(t, "webauthn.create", challenge)
	attObj := map[string]interface{}{
		"fmt":      "none",
		"attStmt":  map[string]interface{}{},
		"authData": a.authData(t, true),
	}
	attBytes, err := cbor.Marshal(attObj)
	if err != nil {
		t.Fatalf("cbor attestation: %v", err)
	}
	return mustJSON(t, map[string]interface{}{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"attestationObject": b64(attBytes),
			"clientDataJSON":    b64(cdj),
		},
	})
}

// login produces an assertion response body for the given base64url challenge,
// incrementing and signing over a fresh counter value.
func (a *softwareAuthenticator) login(t *testing.T, challenge string) []byte {
	t.Helper()
	a.signCnt++
	cdj := a.clientDataJSON(t, "webauthn.get", challenge)
	authData := a.authData(t, false)
	cdjHash := sha256.Sum256(cdj)
	signed := append(append([]byte(nil), authData...), cdjHash[:]...)
	digest := sha256.Sum256(signed)
	sig, err := ecdsa.SignASN1(rand.Reader, a.priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return mustJSON(t, map[string]interface{}{
		"id":    b64(a.credID),
		"rawId": b64(a.credID),
		"type":  "public-key",
		"response": map[string]interface{}{
			"authenticatorData": b64(authData),
			"clientDataJSON":    b64(cdj),
			"signature":         b64(sig),
		},
	})
}

func (a *softwareAuthenticator) clientDataJSON(t *testing.T, typ, challenge string) []byte {
	t.Helper()
	return mustJSON(t, map[string]interface{}{
		"type":      typ,
		"challenge": challenge,
		"origin":    a.origin,
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func mustJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return b
}

// ---- fake authorizer ------------------------------------------------------

type fakeAuthorizer struct {
	bootstrapErr error
	sessionErr   error
	consumed     int
	validated    int
	lastToken    string
	lastSession  string
}

func (f *fakeAuthorizer) ConsumeBootstrapToken(_ context.Context, token string) error {
	f.consumed++
	f.lastToken = token
	return f.bootstrapErr
}

func (f *fakeAuthorizer) ValidateSession(_ context.Context, id string) (model.Session, error) {
	f.validated++
	f.lastSession = id
	if f.sessionErr != nil {
		return model.Session{}, f.sessionErr
	}
	return model.Session{ID: id}, nil
}

// newCeremonyService builds a Service wired for ceremony tests: default loopback
// RP (rp_id 127.0.0.1, origin http://127.0.0.1:7070) plus the given store/authz.
func newCeremonyService(t *testing.T, st Store, az Authorizer) *Service {
	t.Helper()
	svc, err := New(adminCfg(model.ListenConfig{}), st, WithAuthorizer(az))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return svc
}

func newAuthenticatorFor(t *testing.T, svc *Service) *softwareAuthenticator {
	t.Helper()
	return newSoftwareAuthenticator(t, svc.RPID(), svc.RPOrigins()[0])
}

// ---- full ceremonies ------------------------------------------------------

func TestRegisterFirstPasskeyAndLogin(t *testing.T) {
	ctx := context.Background()
	st := &fakeStore{}
	az := &fakeAuthorizer{}
	svc := newCeremonyService(t, st, az)
	auth := newAuthenticatorFor(t, svc)

	// Begin registration gated by a bootstrap token (no session yet).
	creation, chID, err := svc.BeginRegistration(ctx, RegisterGate{BootstrapToken: "pgbt_x", Label: "phone"})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if chID == "" || creation == nil {
		t.Fatal("BeginRegistration returned empty challenge/creation")
	}
	if az.consumed != 0 {
		t.Errorf("bootstrap consumed at Begin = %d, want 0 (consume only at Finish)", az.consumed)
	}

	stored, _, err := svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "pgbt_x", Label: "phone"},
		chID, auth.register(t, creation.Response.Challenge.String()))
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if az.consumed != 1 || az.lastToken != "pgbt_x" {
		t.Errorf("bootstrap consumed = %d token = %q, want 1 / pgbt_x", az.consumed, az.lastToken)
	}
	if !bytes.Equal(stored.CredID, auth.credID) {
		t.Errorf("stored CredID mismatch")
	}
	if stored.Label != "phone" {
		t.Errorf("stored Label = %q, want phone", stored.Label)
	}
	if len(st.inserted) != 1 {
		t.Fatalf("inserted = %d, want 1", len(st.inserted))
	}
	if svc.Challenges().Len() != 0 {
		t.Errorf("challenge not consumed: Len = %d", svc.Challenges().Len())
	}

	// Now log in with the same authenticator.
	assertion, loginID, err := svc.BeginLogin(ctx)
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if assertion == nil || loginID == "" {
		t.Fatal("BeginLogin returned empty assertion/id")
	}
	user, err := svc.FinishLogin(ctx, loginID, auth.login(t, assertion.Response.Challenge.String()))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if user.WebAuthnName() != operatorName {
		t.Errorf("login user = %q, want operator", user.WebAuthnName())
	}
	// Sign count bumped 0 -> 1 and persisted against the stored row id.
	if got := st.updates[stored.ID]; got != 1 {
		t.Errorf("persisted sign count = %d, want 1", got)
	}
}

func TestRegisterAdditionalPasskeyWithSession(t *testing.T) {
	ctx := context.Background()
	// One passkey already exists, so this is the "add another" (session-gated) path.
	st := &fakeStore{creds: []model.WebAuthnCredential{{ID: "wac_0", CredID: []byte{9, 9}, PublicKey: []byte{1}}}}
	az := &fakeAuthorizer{}
	svc := newCeremonyService(t, st, az)
	auth := newAuthenticatorFor(t, svc)

	creation, chID, err := svc.BeginRegistration(ctx, RegisterGate{SessionID: "sess-1"})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if az.validated == 0 {
		t.Error("session not validated at Begin")
	}
	if az.consumed != 0 {
		t.Error("bootstrap should never be consumed on the session path")
	}
	stored, _, err := svc.FinishRegistration(ctx, RegisterGate{SessionID: "sess-1"}, chID,
		auth.register(t, creation.Response.Challenge.String()))
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if !bytes.Equal(stored.CredID, auth.credID) {
		t.Error("stored CredID mismatch")
	}
	if len(st.creds) != 2 {
		t.Errorf("creds = %d, want 2", len(st.creds))
	}
}

// ---- registration gating & error paths ------------------------------------

func TestBeginRegistrationGating(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name    string
		creds   []model.WebAuthnCredential
		gate    RegisterGate
		az      *fakeAuthorizer
		noAuthz bool
		wantErr error
	}{
		{
			name:    "no authorizer configured",
			noAuthz: true,
			wantErr: ErrNoAuthorizer,
		},
		{
			name:    "first passkey missing bootstrap token",
			gate:    RegisterGate{},
			az:      &fakeAuthorizer{},
			wantErr: ErrNotAuthorized,
		},
		{
			name:    "additional passkey missing session",
			creds:   []model.WebAuthnCredential{{ID: "wac_0", CredID: []byte{1}, PublicKey: []byte{2}}},
			gate:    RegisterGate{},
			az:      &fakeAuthorizer{},
			wantErr: ErrNotAuthorized,
		},
		{
			name:    "additional passkey invalid session",
			creds:   []model.WebAuthnCredential{{ID: "wac_0", CredID: []byte{1}, PublicKey: []byte{2}}},
			gate:    RegisterGate{SessionID: "bad"},
			az:      &fakeAuthorizer{sessionErr: errors.New("expired")},
			wantErr: ErrNotAuthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := &fakeStore{creds: tt.creds}
			var svc *Service
			if tt.noAuthz {
				var err error
				svc, err = New(adminCfg(model.ListenConfig{}), st)
				if err != nil {
					t.Fatalf("New: %v", err)
				}
			} else {
				svc = newCeremonyService(t, st, tt.az)
			}
			_, _, err := svc.BeginRegistration(ctx, tt.gate)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("BeginRegistration err = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestBeginRegistrationCountError(t *testing.T) {
	svc := newCeremonyService(t, &fakeStore{countErr: errors.New("db down")}, &fakeAuthorizer{})
	if _, _, err := svc.BeginRegistration(context.Background(), RegisterGate{BootstrapToken: "x"}); err == nil {
		t.Fatal("BeginRegistration with count error = nil, want error")
	}
}

func TestFinishRegistrationErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("no authorizer", func(t *testing.T) {
		svc, err := New(adminCfg(model.ListenConfig{}), &fakeStore{})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if _, _, err := svc.FinishRegistration(ctx, RegisterGate{}, "id", nil); !errors.Is(err, ErrNoAuthorizer) {
			t.Fatalf("err = %v, want ErrNoAuthorizer", err)
		}
	})

	t.Run("unknown challenge", func(t *testing.T) {
		svc := newCeremonyService(t, &fakeStore{}, &fakeAuthorizer{})
		if _, _, err := svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "x"}, "nope", nil); !errors.Is(err, ErrChallengeNotFound) {
			t.Fatalf("err = %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("malformed response body", func(t *testing.T) {
		svc := newCeremonyService(t, &fakeStore{}, &fakeAuthorizer{})
		_, chID, err := svc.BeginRegistration(ctx, RegisterGate{BootstrapToken: "x"})
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		if _, _, err := svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "x"}, chID, []byte("not json")); err == nil {
			t.Fatal("FinishRegistration with bad body = nil, want error")
		}
	})

	t.Run("bootstrap consume fails after verify", func(t *testing.T) {
		st := &fakeStore{}
		az := &fakeAuthorizer{bootstrapErr: errors.New("used")}
		svc := newCeremonyService(t, st, az)
		auth := newAuthenticatorFor(t, svc)
		creation, chID, err := svc.BeginRegistration(ctx, RegisterGate{BootstrapToken: "x"})
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		_, _, err = svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "x"}, chID,
			auth.register(t, creation.Response.Challenge.String()))
		if !errors.Is(err, ErrNotAuthorized) {
			t.Fatalf("err = %v, want ErrNotAuthorized", err)
		}
		if len(st.inserted) != 0 {
			t.Errorf("credential stored despite failed gate: %d", len(st.inserted))
		}
	})

	t.Run("insert fails", func(t *testing.T) {
		st := &fakeStore{insertErr: errors.New("disk full")}
		svc := newCeremonyService(t, st, &fakeAuthorizer{})
		auth := newAuthenticatorFor(t, svc)
		creation, chID, err := svc.BeginRegistration(ctx, RegisterGate{BootstrapToken: "x"})
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		if _, _, err := svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "x"}, chID,
			auth.register(t, creation.Response.Challenge.String())); err == nil {
			t.Fatal("FinishRegistration with insert error = nil, want error")
		}
	})

	t.Run("verify fails on tampered challenge", func(t *testing.T) {
		svc := newCeremonyService(t, &fakeStore{}, &fakeAuthorizer{})
		auth := newAuthenticatorFor(t, svc)
		_, chID, err := svc.BeginRegistration(ctx, RegisterGate{BootstrapToken: "x"})
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		// Sign a different challenge than the ceremony expects.
		if _, _, err := svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "x"}, chID,
			auth.register(t, b64([]byte("wrong-challenge-value-000")))); err == nil {
			t.Fatal("FinishRegistration with wrong challenge = nil, want error")
		}
	})
}

// ---- login error paths ----------------------------------------------------

func TestBeginLoginNoCredentials(t *testing.T) {
	svc := newCeremonyService(t, &fakeStore{}, &fakeAuthorizer{})
	if _, _, err := svc.BeginLogin(context.Background()); !errors.Is(err, ErrNoCredentials) {
		t.Fatalf("err = %v, want ErrNoCredentials", err)
	}
}

func TestBeginLoginStoreError(t *testing.T) {
	svc := newCeremonyService(t, &fakeStore{err: errors.New("boom")}, &fakeAuthorizer{})
	if _, _, err := svc.BeginLogin(context.Background()); err == nil {
		t.Fatal("BeginLogin with store error = nil, want error")
	}
}

func TestFinishLoginErrors(t *testing.T) {
	ctx := context.Background()

	// Register a passkey first so login has something to validate against.
	setup := func(t *testing.T) (*Service, *fakeStore, *softwareAuthenticator, *webauthnAssertionFixture) {
		t.Helper()
		st := &fakeStore{}
		svc := newCeremonyService(t, st, &fakeAuthorizer{})
		auth := newAuthenticatorFor(t, svc)
		creation, chID, err := svc.BeginRegistration(ctx, RegisterGate{BootstrapToken: "x"})
		if err != nil {
			t.Fatalf("BeginRegistration: %v", err)
		}
		if _, _, err := svc.FinishRegistration(ctx, RegisterGate{BootstrapToken: "x"}, chID,
			auth.register(t, creation.Response.Challenge.String())); err != nil {
			t.Fatalf("FinishRegistration: %v", err)
		}
		assertion, loginID, err := svc.BeginLogin(ctx)
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		return svc, st, auth, &webauthnAssertionFixture{loginID: loginID, challenge: assertion.Response.Challenge.String()}
	}

	t.Run("unknown challenge", func(t *testing.T) {
		svc, _, _, _ := setup(t)
		if _, err := svc.FinishLogin(ctx, "nope", nil); !errors.Is(err, ErrChallengeNotFound) {
			t.Fatalf("err = %v, want ErrChallengeNotFound", err)
		}
	})

	t.Run("malformed body", func(t *testing.T) {
		svc, _, _, fx := setup(t)
		if _, err := svc.FinishLogin(ctx, fx.loginID, []byte("nope")); err == nil {
			t.Fatal("FinishLogin with bad body = nil, want error")
		}
	})

	t.Run("verify fails on tampered challenge", func(t *testing.T) {
		svc, _, auth, fx := setup(t)
		if _, err := svc.FinishLogin(ctx, fx.loginID, auth.login(t, b64([]byte("some-other-challenge0")))); err == nil {
			t.Fatal("FinishLogin with wrong challenge = nil, want error")
		}
	})

	t.Run("credential lookup fails", func(t *testing.T) {
		svc, st, auth, fx := setup(t)
		st.getErr = errors.New("lookup boom")
		if _, err := svc.FinishLogin(ctx, fx.loginID, auth.login(t, fx.challenge)); err == nil {
			t.Fatal("FinishLogin with lookup error = nil, want error")
		}
	})

	t.Run("sign-count update fails", func(t *testing.T) {
		svc, st, auth, fx := setup(t)
		st.updateErr = errors.New("update boom")
		if _, err := svc.FinishLogin(ctx, fx.loginID, auth.login(t, fx.challenge)); err == nil {
			t.Fatal("FinishLogin with update error = nil, want error")
		}
	})
}

type webauthnAssertionFixture struct {
	loginID   string
	challenge string
}
