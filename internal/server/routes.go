// server/routes.go — updated router with all Batch 3a endpoints.
//
// Phase 1 baseline lived inline in server.go; Batch 3a factors it out and
// adds: change-password, usage, admin quota / password / delete user /
// delete invite / extend invite.
//
// Batch 3.3 Group 1c: adds /auth/verify for broker reverse-validation
// of client JWTs. This route uses serviceTokenMiddleware (Bearer service
// token) and is intentionally NOT under the JWT auth group — it
// authenticates a service, not a user.

package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/rulinye/zerolink-backend/internal/auth"
)

// buildRouter returns the fully-wired chi router. Called once from New().
func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(s.requestLogger())
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Unauthenticated routes.
	r.Get("/ping", s.handlePing)
	r.Get("/version", s.handleVersion)
	r.Get("/sub/{token}", s.handleSubscriptionFetch)

	// JSON API.
	r.Route("/api/v1", func(r chi.Router) {
		// Open.
		r.Post("/auth/register", s.handleRegister)
		r.Post("/auth/login", s.handleLogin)

		// Service-authenticated (broker -> backend reverse-verify).
		// Uses Bearer service_token, NOT user JWT. See
		// service_token_middleware.go for the lookup details.
		r.Group(func(r chi.Router) {
			r.Use(s.serviceTokenMiddleware)
			r.Post("/auth/verify", s.handleVerifyJWT)
			// B4.7-supp / B6: per-broker enabled status. Brokers poll
			// every 15s and reject create/join when their own
			// broker_enabled flips to false (defense in depth alongside
			// client-side filtering of has_broker=false from /api/v1/nodes).
			r.Get("/broker-status", s.handleBrokerStatus)
		})

		// Authenticated (user).
		r.Group(func(r chi.Router) {
			r.Use(auth.Middleware(s.signer, s.db.Users, s.db.Tokens))

			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/logout", s.handleLogout)
			r.Post("/auth/change-password", s.handleChangePassword)

			r.Get("/nodes", s.handleListNodes)
			r.Get("/nodes/{id}/config", s.handleNodeConfig)

			r.Get("/subscriptions", s.handleListSubscriptions)
			r.Post("/subscriptions", s.handleCreateSubscription)
			r.Delete("/subscriptions/{token}", s.handleRevokeSubscription)

			r.Get("/usage/me", s.handleGetMyUsage)

			// Admin.
			r.Group(func(r chi.Router) {
				r.Use(auth.AdminOnly)

				// Users.
				r.Get("/admin/users", s.handleAdminListUsers)
				r.Post("/admin/users/{id}/disable", s.handleAdminToggleUser)
				r.Post("/admin/users/{id}/quota", s.handleAdminSetUserQuota)
				r.Post("/admin/users/{id}/password", s.handleAdminSetUserPassword)
				r.Delete("/admin/users/{id}", s.handleAdminDeleteUser)

				// Invites.
				r.Get("/admin/invites", s.handleAdminListInvites)
				r.Post("/admin/invites", s.handleAdminCreateInvite)
				r.Delete("/admin/invites/{code}", s.handleAdminDeleteInvite)
				r.Post("/admin/invites/{code}/extend", s.handleAdminExtendInvite)

				// Nodes.
				r.Get("/admin/nodes", s.handleAdminListNodes)
				r.Patch("/admin/nodes/{id}/broker", s.handleAdminToggleBroker)
			})
		})
	})

	// Admin HTML UI (unchanged; kept as emergency fallback per D2.14).
	if s.cfg.AdminUIEnabled {
		r.Route("/admin", func(r chi.Router) {
			r.Get("/login", s.handleUILogin)
			r.Post("/login", s.handleUILoginSubmit)
			r.Get("/logout", s.handleUILogout)

			r.Group(func(r chi.Router) {
				r.Use(s.cookieAuthMiddleware)
				r.Get("/", s.handleUIDashboard)
				r.Get("/invites", s.handleUIInvites)
				r.Post("/invites", s.handleUICreateInvite)
				r.Get("/users", s.handleUIUsers)
				r.Get("/nodes", s.handleUINodes)
			})
		})
		if s.staticFS != nil {
			r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(s.staticFS))))
		}
	}

	return r
}
