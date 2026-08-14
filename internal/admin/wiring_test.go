package admin

import (
	"github.com/go2-im/poolgate/internal/adminauth"
	"github.com/go2-im/poolgate/internal/store"
	"github.com/go2-im/poolgate/internal/webauthnsvc"
)

// Compile-time proof that the production types satisfy the admin interfaces, so
// the API is genuinely reusable (not just fake-tested).
var (
	_ Store          = (*store.Store)(nil)
	_ SessionManager = (*adminauth.Manager)(nil)
	_ Ceremonies     = (*webauthnsvc.Service)(nil)
)
