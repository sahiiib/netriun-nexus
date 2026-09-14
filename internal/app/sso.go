package app

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/jackc/pgx/v5"
	"github.com/netriun/nexus/internal/secure"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

type identityProviderConfig struct {
	IssuerURL         string   `json:"issuer_url,omitempty"`
	ClientID          string   `json:"client_id,omitempty"`
	ClientSecret      string   `json:"client_secret,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	EmailClaim        string   `json:"email_claim,omitempty"`
	UsernameClaim     string   `json:"username_claim,omitempty"`
	GroupsClaim       string   `json:"groups_claim,omitempty"`
	IDPMetadata       string   `json:"idp_metadata,omitempty"`
	EmailAttribute    string   `json:"email_attribute,omitempty"`
	UsernameAttribute string   `json:"username_attribute,omitempty"`
	GroupsAttribute   string   `json:"groups_attribute,omitempty"`
	SPCertificate     string   `json:"sp_certificate,omitempty"`
	SPPrivateKey      string   `json:"sp_private_key,omitempty"`
}

type identityProviderInput struct {
	Name            string                 `json:"name"`
	Protocol        string                 `json:"protocol"`
	Enabled         bool                   `json:"enabled"`
	JITProvisioning bool                   `json:"jit_provisioning"`
	Config          identityProviderConfig `json:"config"`
}

type identityProvider struct {
	ID              int64
	WorkspaceID     int64
	PublicID        string
	Name            string
	Protocol        string
	Enabled         bool
	JITProvisioning bool
	EncryptedConfig string
}

type ssoState struct {
	ProviderID int64  `json:"provider_id"`
	Nonce      string `json:"nonce,omitempty"`
	Verifier   string `json:"verifier,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
}

type ssoIdentity struct {
	Subject       string
	Email         string
	EmailVerified bool
	Username      string
	Groups        []string
	Attributes    map[string]any
}

func (a *App) identityProviders(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	u := current(r)
	rows, err := a.DB.Query(r.Context(), `SELECT id,public_id,name,protocol,enabled,jit_provisioning,config_encrypted,created_at,updated_at FROM identity_providers WHERE workspace_id=$1 ORDER BY name`, u.WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	defer rows.Close()
	providers := []map[string]any{}
	for rows.Next() {
		var p identityProvider
		var createdAt, updatedAt time.Time
		if err = rows.Scan(&p.ID, &p.PublicID, &p.Name, &p.Protocol, &p.Enabled, &p.JITProvisioning, &p.EncryptedConfig, &createdAt, &updatedAt); err != nil {
			dbError(w, err)
			return
		}
		cfg, err := a.decryptIdentityProviderConfig(p.EncryptedConfig)
		if err != nil {
			dbError(w, err)
			return
		}
		safe := map[string]any{
			"issuer_url": cfg.IssuerURL, "client_id": cfg.ClientID, "scopes": cfg.Scopes,
			"email_claim": cfg.EmailClaim, "username_claim": cfg.UsernameClaim, "groups_claim": cfg.GroupsClaim,
			"email_attribute": cfg.EmailAttribute, "username_attribute": cfg.UsernameAttribute, "groups_attribute": cfg.GroupsAttribute,
			"client_secret_configured": cfg.ClientSecret != "", "idp_metadata_configured": cfg.IDPMetadata != "",
		}
		providers = append(providers, map[string]any{
			"id": p.ID, "public_id": p.PublicID, "name": p.Name, "protocol": p.Protocol, "enabled": p.Enabled,
			"jit_provisioning": p.JITProvisioning, "config": safe, "login_url": a.Origin + "/sso/" + p.PublicID + "/start",
			"callback_url": a.Origin + "/sso/" + p.PublicID + "/callback", "metadata_url": a.Origin + "/sso/" + p.PublicID + "/metadata", "created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if err = rows.Err(); err != nil {
		dbError(w, err)
		return
	}
	var required bool
	var workspaceSlug string
	if err = a.DB.QueryRow(r.Context(), "SELECT sso_required,slug FROM workspaces WHERE id=$1", u.WorkspaceID).Scan(&required, &workspaceSlug); err != nil {
		dbError(w, err)
		return
	}
	write(w, 200, map[string]any{"data": providers, "sso_required": required, "workspace_slug": workspaceSlug})
}

func (a *App) saveIdentityProvider(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in identityProviderInput
	if !decode(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	in.Protocol = strings.ToLower(strings.TrimSpace(in.Protocol))
	if len(in.Name) < 1 || len(in.Name) > 100 || (in.Protocol != "oidc" && in.Protocol != "saml") {
		problem(w, 400, "Provide a name and choose OIDC or SAML")
		return
	}
	u := current(r)
	var id int64
	var publicID string
	if r.Method == http.MethodPut {
		var ok bool
		id, ok = pathID(w, r, "id")
		if !ok {
			return
		}
		var encrypted, protocol string
		if err := a.DB.QueryRow(r.Context(), "SELECT public_id,protocol,config_encrypted FROM identity_providers WHERE id=$1 AND workspace_id=$2", id, u.WorkspaceID).Scan(&publicID, &protocol, &encrypted); err != nil {
			dbError(w, err)
			return
		}
		if protocol != in.Protocol {
			problem(w, 400, "Create a new provider to change the SSO protocol")
			return
		}
		previous, err := a.decryptIdentityProviderConfig(encrypted)
		if err != nil {
			dbError(w, err)
			return
		}
		mergeIdentityProviderSecrets(&in.Config, previous)
		if in.Protocol == "oidc" && strings.TrimRight(strings.TrimSpace(previous.IssuerURL), "/") != strings.TrimRight(strings.TrimSpace(in.Config.IssuerURL), "/") {
			problem(w, 400, "Create a new provider to change the OIDC issuer")
			return
		}
		if in.Protocol == "saml" && in.Config.IDPMetadata != previous.IDPMetadata {
			oldMetadata, oldErr := samlsp.ParseMetadata([]byte(previous.IDPMetadata))
			newMetadata, newErr := samlsp.ParseMetadata([]byte(in.Config.IDPMetadata))
			if oldErr != nil || newErr != nil || oldMetadata.EntityID != newMetadata.EntityID {
				problem(w, 400, "Create a new provider to change the SAML IdP entity ID")
				return
			}
		}
		if !in.Enabled {
			var required, anotherEnabled bool
			if err := a.DB.QueryRow(r.Context(), "SELECT w.sso_required,EXISTS(SELECT 1 FROM identity_providers other WHERE other.workspace_id=w.id AND other.enabled AND other.id<>$2) FROM workspaces w WHERE w.id=$1", u.WorkspaceID, id).Scan(&required, &anotherEnabled); err != nil {
				dbError(w, err)
				return
			}
			if required && !anotherEnabled {
				problem(w, 409, "Disable SSO enforcement before disabling the last identity provider")
				return
			}
		}
	} else {
		publicID = secure.Token()
	}
	if err := normalizeIdentityProviderConfig(in.Protocol, &in.Config, a.Origin, publicID); err != nil {
		problem(w, 400, err.Error())
		return
	}
	if in.Enabled {
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		if in.Protocol == "oidc" {
			if _, err := oidc.NewProvider(ctx, in.Config.IssuerURL); err != nil {
				problem(w, 400, "OIDC discovery failed; verify the HTTPS issuer and try again")
				return
			}
		} else {
			candidate := identityProvider{PublicID: publicID, Protocol: "saml"}
			if _, err := a.samlServiceProvider(candidate, in.Config); err != nil {
				problem(w, 400, "SAML metadata or service-provider certificate validation failed")
				return
			}
		}
	}
	encoded, err := json.Marshal(in.Config)
	if err != nil {
		problem(w, 500, "Could not encode identity-provider configuration")
		return
	}
	cipher := a.Vault.Encrypt(string(encoded))
	if r.Method == http.MethodPost {
		err = a.DB.QueryRow(r.Context(), `INSERT INTO identity_providers(workspace_id,public_id,name,protocol,enabled,jit_provisioning,config_encrypted) VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, u.WorkspaceID, publicID, in.Name, in.Protocol, in.Enabled, in.JITProvisioning, cipher).Scan(&id)
	} else {
		err = a.DB.QueryRow(r.Context(), `UPDATE identity_providers SET name=$1,enabled=$2,jit_provisioning=$3,config_encrypted=$4,updated_at=now() WHERE id=$5 AND workspace_id=$6 RETURNING id`, in.Name, in.Enabled, in.JITProvisioning, cipher, id, u.WorkspaceID).Scan(&id)
	}
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "identity_provider.saved", fmt.Sprint(id), map[string]any{"name": in.Name, "protocol": in.Protocol, "enabled": in.Enabled, "jit_provisioning": in.JITProvisioning})
	write(w, 200, map[string]any{"id": id, "public_id": publicID})
}

func mergeIdentityProviderSecrets(current *identityProviderConfig, previous identityProviderConfig) {
	if current.ClientSecret == "" {
		current.ClientSecret = previous.ClientSecret
	}
	if current.IDPMetadata == "" {
		current.IDPMetadata = previous.IDPMetadata
	}
	if current.SPCertificate == "" {
		current.SPCertificate = previous.SPCertificate
	}
	if current.SPPrivateKey == "" {
		current.SPPrivateKey = previous.SPPrivateKey
	}
}

func normalizeIdentityProviderConfig(protocol string, cfg *identityProviderConfig, origin, publicID string) error {
	if protocol == "oidc" {
		cfg.IssuerURL = strings.TrimRight(strings.TrimSpace(cfg.IssuerURL), "/")
		issuer, err := url.Parse(cfg.IssuerURL)
		if err != nil || issuer.Scheme != "https" || issuer.Host == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
			return errors.New("OIDC requires an HTTPS issuer URL, client ID, and client secret")
		}
		cfg.EmailClaim = defaultString(cfg.EmailClaim, "email")
		cfg.UsernameClaim = defaultString(cfg.UsernameClaim, "preferred_username")
		cfg.GroupsClaim = defaultString(cfg.GroupsClaim, "groups")
		if len(cfg.Scopes) == 0 {
			cfg.Scopes = []string{"openid", "profile", "email", "groups"}
		}
		if !slices.Contains(cfg.Scopes, "openid") {
			cfg.Scopes = append([]string{"openid"}, cfg.Scopes...)
		}
		return nil
	}
	if cfg.IDPMetadata == "" {
		return errors.New("SAML requires IdP metadata XML")
	}
	if _, err := samlsp.ParseMetadata([]byte(cfg.IDPMetadata)); err != nil {
		return errors.New("SAML IdP metadata is invalid")
	}
	cfg.EmailAttribute = defaultString(cfg.EmailAttribute, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress")
	cfg.UsernameAttribute = defaultString(cfg.UsernameAttribute, "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name")
	cfg.GroupsAttribute = defaultString(cfg.GroupsAttribute, "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups")
	if cfg.SPCertificate == "" || cfg.SPPrivateKey == "" {
		cert, key, err := generateSAMLKeyPair(origin + "/sso/" + publicID)
		if err != nil {
			return errors.New("could not generate the SAML service-provider certificate")
		}
		cfg.SPCertificate, cfg.SPPrivateKey = cert, key
	}
	return nil
}

func defaultString(value, fallback string) string {
	if value = strings.TrimSpace(value); value != "" {
		return value
	}
	return fallback
}

func generateSAMLKeyPair(commonName string) (string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	template := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: commonName, Organization: []string{"Netriun Nexus"}}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(5, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return string(certPEM), string(keyPEM), nil
}

func (a *App) deleteIdentityProvider(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	var required, deletingEnabled, anotherEnabled bool
	if err := a.DB.QueryRow(r.Context(), `SELECT w.sso_required,p.enabled,EXISTS(SELECT 1 FROM identity_providers other WHERE other.workspace_id=w.id AND other.enabled AND other.id<>p.id) FROM identity_providers p JOIN workspaces w ON w.id=p.workspace_id WHERE p.id=$1 AND p.workspace_id=$2`, id, current(r).WorkspaceID).Scan(&required, &deletingEnabled, &anotherEnabled); err != nil {
		dbError(w, err)
		return
	}
	if required && deletingEnabled && !anotherEnabled {
		problem(w, 409, "Disable SSO enforcement before deleting the last identity provider")
		return
	}
	tag, err := a.DB.Exec(r.Context(), "DELETE FROM identity_providers WHERE id=$1 AND workspace_id=$2", id, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	if tag.RowsAffected() == 0 {
		problem(w, 404, "Identity provider not found")
		return
	}
	a.audit(r, "identity_provider.deleted", fmt.Sprint(id), nil)
	write(w, 200, map[string]bool{"ok": true})
}

func (a *App) saveSSOSettings(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	var in struct {
		Required bool `json:"sso_required"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Required {
		var enabled bool
		if err := a.DB.QueryRow(r.Context(), "SELECT EXISTS(SELECT 1 FROM identity_providers WHERE workspace_id=$1 AND enabled)", current(r).WorkspaceID).Scan(&enabled); err != nil {
			dbError(w, err)
			return
		}
		if !enabled {
			problem(w, 400, "Enable at least one identity provider before requiring SSO")
			return
		}
	}
	_, err := a.DB.Exec(r.Context(), "UPDATE workspaces SET sso_required=$1 WHERE id=$2", in.Required, current(r).WorkspaceID)
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "sso.enforcement_updated", "", in)
	write(w, 200, map[string]bool{"ok": true})
}

func (a *App) identityGroupMappings(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	if r.Method == http.MethodGet {
		a.list(w, r, `SELECT row_to_json(t) FROM (SELECT m.id,m.external_group,m.group_id,g.name AS group_name,m.membership_role FROM identity_group_mappings m JOIN access_groups g ON g.id=m.group_id AND g.workspace_id=m.workspace_id WHERE m.provider_id=$1 AND m.workspace_id=$2 ORDER BY m.external_group,g.name) t`, id, current(r).WorkspaceID)
		return
	}
	var in struct {
		ExternalGroup  string `json:"external_group"`
		GroupID        int64  `json:"group_id"`
		MembershipRole string `json:"membership_role"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.ExternalGroup = strings.TrimSpace(in.ExternalGroup)
	if in.ExternalGroup == "" || len(in.ExternalGroup) > 512 || in.GroupID < 1 || !slices.Contains([]string{"viewer", "operator", "manager"}, in.MembershipRole) {
		problem(w, 400, "Provide an external group, Nexus team, and membership role")
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var mappingID int64
	err = tx.QueryRow(r.Context(), `INSERT INTO identity_group_mappings(workspace_id,provider_id,external_group,group_id,membership_role) SELECT $1,p.id,$3,g.id,$5 FROM identity_providers p JOIN access_groups g ON g.id=$4 AND g.workspace_id=p.workspace_id WHERE p.id=$2 AND p.workspace_id=$1 ON CONFLICT(provider_id,external_group,group_id) DO UPDATE SET membership_role=excluded.membership_role RETURNING id`, current(r).WorkspaceID, id, in.ExternalGroup, in.GroupID, in.MembershipRole).Scan(&mappingID)
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE sso_membership_grants SET role=$1,synced_at=now() WHERE workspace_id=$2 AND provider_id=$3 AND external_group=$4 AND group_id=$5", in.MembershipRole, current(r).WorkspaceID, id, in.ExternalGroup, in.GroupID)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "identity_group_mapping.saved", fmt.Sprint(mappingID), in)
	write(w, 200, map[string]int64{"id": mappingID})
}

func (a *App) deleteIdentityGroupMapping(w http.ResponseWriter, r *http.Request) {
	if !admin(w, r) {
		return
	}
	providerID, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	mappingID, ok := pathID(w, r, "mappingID")
	if !ok {
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		dbError(w, err)
		return
	}
	defer tx.Rollback(r.Context())
	var externalGroup string
	var groupID int64
	err = tx.QueryRow(r.Context(), "DELETE FROM identity_group_mappings WHERE id=$1 AND provider_id=$2 AND workspace_id=$3 RETURNING external_group,group_id", mappingID, providerID, current(r).WorkspaceID).Scan(&externalGroup, &groupID)
	if errors.Is(err, pgx.ErrNoRows) {
		problem(w, 404, "Group mapping not found")
		return
	}
	if err != nil {
		dbError(w, err)
		return
	}
	if _, err = tx.Exec(r.Context(), "DELETE FROM sso_membership_grants WHERE workspace_id=$1 AND provider_id=$2 AND external_group=$3 AND group_id=$4", current(r).WorkspaceID, providerID, externalGroup, groupID); err != nil {
		dbError(w, err)
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		dbError(w, err)
		return
	}
	a.audit(r, "identity_group_mapping.deleted", fmt.Sprint(mappingID), nil)
	write(w, 200, map[string]bool{"ok": true})
}

func (a *App) publicIdentityProviders(w http.ResponseWriter, r *http.Request) {
	if !a.allowAttempt(r, "sso-discovery", 60) {
		w.Header().Set("Retry-After", "300")
		problem(w, 429, "Too many SSO discovery requests; try again later")
		return
	}
	workspace := strings.TrimSpace(r.URL.Query().Get("workspace"))
	if workspace == "" {
		problem(w, 400, "Workspace SSO code is required")
		return
	}
	a.list(w, r, `SELECT row_to_json(t) FROM (SELECT p.public_id,p.name,p.protocol,'/sso/'||p.public_id||'/start' AS login_url FROM identity_providers p JOIN workspaces w ON w.id=p.workspace_id WHERE w.slug=$1 AND p.enabled ORDER BY p.name) t`, workspace)
}

func (a *App) loadIdentityProvider(ctx context.Context, publicID string, enabledOnly bool) (identityProvider, identityProviderConfig, error) {
	var p identityProvider
	query := "SELECT id,workspace_id,public_id,name,protocol,enabled,jit_provisioning,config_encrypted FROM identity_providers WHERE public_id=$1"
	if enabledOnly {
		query += " AND enabled"
	}
	err := a.DB.QueryRow(ctx, query, publicID).Scan(&p.ID, &p.WorkspaceID, &p.PublicID, &p.Name, &p.Protocol, &p.Enabled, &p.JITProvisioning, &p.EncryptedConfig)
	if err != nil {
		return p, identityProviderConfig{}, err
	}
	cfg, err := a.decryptIdentityProviderConfig(p.EncryptedConfig)
	return p, cfg, err
}

func (a *App) decryptIdentityProviderConfig(cipher string) (identityProviderConfig, error) {
	plain, err := a.Vault.Decrypt(cipher)
	if err != nil {
		return identityProviderConfig{}, err
	}
	var cfg identityProviderConfig
	err = json.Unmarshal([]byte(plain), &cfg)
	return cfg, err
}

func (a *App) startSSO(w http.ResponseWriter, r *http.Request) {
	p, cfg, err := a.loadIdentityProvider(r.Context(), r.PathValue("provider"), true)
	if err != nil {
		http.Redirect(w, r, "/?sso=unavailable", http.StatusSeeOther)
		return
	}
	stateToken := secure.Token()
	state := ssoState{ProviderID: p.ID}
	var destination string
	if p.Protocol == "oidc" {
		provider, err := oidc.NewProvider(r.Context(), cfg.IssuerURL)
		if err != nil {
			http.Redirect(w, r, "/?sso=unavailable", http.StatusSeeOther)
			return
		}
		state.Nonce, state.Verifier = secure.Token(), secure.Token()
		oauth := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: a.Origin + "/sso/" + p.PublicID + "/callback", Endpoint: provider.Endpoint(), Scopes: cfg.Scopes}
		sum := sha256.Sum256([]byte(state.Verifier))
		destination = oauth.AuthCodeURL(stateToken, oidc.Nonce(state.Nonce), oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(sum[:])), oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	} else {
		sp, err := a.samlServiceProvider(p, cfg)
		if err != nil {
			http.Redirect(w, r, "/?sso=unavailable", http.StatusSeeOther)
			return
		}
		location := sp.GetSSOBindingLocation(saml.HTTPRedirectBinding)
		request, err := sp.MakeAuthenticationRequest(location, saml.HTTPRedirectBinding, saml.HTTPPostBinding)
		if err != nil {
			http.Redirect(w, r, "/?sso=unavailable", http.StatusSeeOther)
			return
		}
		state.RequestID = request.ID
		redirect, err := request.Redirect(stateToken, sp)
		if err != nil {
			http.Redirect(w, r, "/?sso=unavailable", http.StatusSeeOther)
			return
		}
		destination = redirect.String()
	}
	raw, _ := json.Marshal(state)
	if err = a.Redis.Set(r.Context(), "sso-state:"+secure.Digest(stateToken), raw, 10*time.Minute).Err(); err != nil {
		http.Redirect(w, r, "/?sso=unavailable", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, destination, http.StatusFound)
}

func (a *App) oidcCallback(w http.ResponseWriter, r *http.Request) {
	p, cfg, state, ok := a.consumeSSOState(w, r, r.URL.Query().Get("state"), "oidc")
	if !ok {
		return
	}
	provider, err := oidc.NewProvider(r.Context(), cfg.IssuerURL)
	if err != nil {
		a.ssoFailure(w, r)
		return
	}
	oauth := oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, RedirectURL: a.Origin + "/sso/" + p.PublicID + "/callback", Endpoint: provider.Endpoint(), Scopes: cfg.Scopes}
	token, err := oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(state.Verifier))
	if err != nil {
		a.ssoFailure(w, r)
		return
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		a.ssoFailure(w, r)
		return
	}
	idToken, err := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}).Verify(r.Context(), rawIDToken)
	if err != nil || idToken.Nonce != state.Nonce {
		a.ssoFailure(w, r)
		return
	}
	claims := map[string]any{}
	if err = idToken.Claims(&claims); err != nil {
		a.ssoFailure(w, r)
		return
	}
	identity := ssoIdentity{Subject: idToken.Subject, Email: firstClaim(claims, cfg.EmailClaim), Username: firstClaim(claims, cfg.UsernameClaim), Groups: claimValues(claims, cfg.GroupsClaim), Attributes: claims}
	identity.EmailVerified = claimBool(claims, "email_verified")
	a.finishSSO(w, r, p, identity)
}

func (a *App) samlMetadata(w http.ResponseWriter, r *http.Request) {
	p, cfg, err := a.loadIdentityProvider(r.Context(), r.PathValue("provider"), false)
	if err != nil || p.Protocol != "saml" {
		http.NotFound(w, r)
		return
	}
	sp, err := a.samlServiceProvider(p, cfg)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	b, err := xml.MarshalIndent(sp.Metadata(), "", "  ")
	if err != nil {
		http.Error(w, "metadata unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.Write([]byte(xml.Header))
	w.Write(b)
}

func (a *App) samlCallback(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		a.ssoFailure(w, r)
		return
	}
	stateToken := r.FormValue("RelayState")
	p, cfg, state, ok := a.consumeSSOState(w, r, stateToken, "saml")
	if !ok {
		return
	}
	sp, err := a.samlServiceProvider(p, cfg)
	if err != nil {
		a.ssoFailure(w, r)
		return
	}
	assertion, err := sp.ParseResponse(r, []string{state.RequestID})
	if err != nil || assertion.Subject == nil || assertion.Subject.NameID == nil || assertion.Subject.NameID.Format != string(saml.PersistentNameIDFormat) {
		a.ssoFailure(w, r)
		return
	}
	attributes := map[string]any{}
	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			values := []string{}
			for _, value := range attribute.Values {
				values = append(values, strings.TrimSpace(value.Value))
			}
			attributes[attribute.Name] = values
			if attribute.FriendlyName != "" {
				attributes[attribute.FriendlyName] = values
			}
		}
	}
	identity := ssoIdentity{Subject: strings.TrimSpace(assertion.Subject.NameID.Value), Email: firstClaim(attributes, cfg.EmailAttribute), Username: firstClaim(attributes, cfg.UsernameAttribute), Groups: claimValues(attributes, cfg.GroupsAttribute), EmailVerified: true, Attributes: attributes}
	a.finishSSO(w, r, p, identity)
}

func (a *App) consumeSSOState(w http.ResponseWriter, r *http.Request, token, protocol string) (identityProvider, identityProviderConfig, ssoState, bool) {
	var state ssoState
	if token == "" {
		a.ssoFailure(w, r)
		return identityProvider{}, identityProviderConfig{}, state, false
	}
	key := "sso-state:" + secure.Digest(token)
	raw, err := a.Redis.GetDel(r.Context(), key).Bytes()
	if err != nil || json.Unmarshal(raw, &state) != nil {
		a.ssoFailure(w, r)
		return identityProvider{}, identityProviderConfig{}, state, false
	}
	var publicID string
	if err = a.DB.QueryRow(r.Context(), "SELECT public_id FROM identity_providers WHERE id=$1", state.ProviderID).Scan(&publicID); err != nil {
		a.ssoFailure(w, r)
		return identityProvider{}, identityProviderConfig{}, state, false
	}
	p, cfg, err := a.loadIdentityProvider(r.Context(), publicID, true)
	if err != nil || p.Protocol != protocol || p.PublicID != r.PathValue("provider") {
		a.ssoFailure(w, r)
		return identityProvider{}, identityProviderConfig{}, state, false
	}
	return p, cfg, state, true
}

func (a *App) samlServiceProvider(p identityProvider, cfg identityProviderConfig) (*saml.ServiceProvider, error) {
	metadata, err := samlsp.ParseMetadata([]byte(cfg.IDPMetadata))
	if err != nil {
		return nil, err
	}
	keyPair, err := tls.X509KeyPair([]byte(cfg.SPCertificate), []byte(cfg.SPPrivateKey))
	if err != nil {
		return nil, err
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		return nil, err
	}
	metadataURL, _ := url.Parse(a.Origin + "/sso/" + p.PublicID + "/metadata")
	acsURL, _ := url.Parse(a.Origin + "/sso/" + p.PublicID + "/acs")
	return &saml.ServiceProvider{EntityID: metadataURL.String(), Key: keyPair.PrivateKey.(*rsa.PrivateKey), Certificate: keyPair.Leaf, MetadataURL: *metadataURL, AcsURL: *acsURL, IDPMetadata: metadata, AuthnNameIDFormat: saml.PersistentNameIDFormat, SignatureMethod: "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}, nil
}

func (a *App) finishSSO(w http.ResponseWriter, r *http.Request, p identityProvider, identity ssoIdentity) {
	identity.Subject, identity.Email, identity.Username = strings.TrimSpace(identity.Subject), strings.ToLower(strings.TrimSpace(identity.Email)), strings.TrimSpace(identity.Username)
	if identity.Subject == "" || identity.Email == "" || !identity.EmailVerified {
		a.ssoFailure(w, r)
		return
	}
	if _, err := normalizeEmail(identity.Email); err != nil {
		a.ssoFailure(w, r)
		return
	}
	tx, err := a.DB.Begin(r.Context())
	if err != nil {
		a.ssoFailure(w, r)
		return
	}
	defer tx.Rollback(r.Context())
	if _, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock($1)", p.WorkspaceID); err != nil {
		a.ssoFailure(w, r)
		return
	}
	var u User
	err = tx.QueryRow(r.Context(), `SELECT u.id,u.workspace_id,w.name,u.username,u.email,u.role,u.is_owner,u.session_version FROM external_identities e JOIN users u ON u.id=e.user_id JOIN workspaces w ON w.id=u.workspace_id WHERE e.provider_id=$1 AND e.subject=$2`, p.ID, identity.Subject).Scan(&u.ID, &u.WorkspaceID, &u.WorkspaceName, &u.Username, &u.Email, &u.Role, &u.IsOwner, &u.Version)
	if errors.Is(err, pgx.ErrNoRows) {
		err = tx.QueryRow(r.Context(), `SELECT u.id,u.workspace_id,w.name,u.username,u.email,u.role,u.is_owner,u.session_version FROM users u JOIN workspaces w ON w.id=u.workspace_id WHERE u.workspace_id=$1 AND lower(u.email)=$2`, p.WorkspaceID, identity.Email).Scan(&u.ID, &u.WorkspaceID, &u.WorkspaceName, &u.Username, &u.Email, &u.Role, &u.IsOwner, &u.Version)
		if errors.Is(err, pgx.ErrNoRows) && p.JITProvisioning {
			var count, limit int
			if err = tx.QueryRow(r.Context(), "SELECT count(*),max(w.user_limit) FROM users existing JOIN workspaces w ON w.id=existing.workspace_id WHERE existing.workspace_id=$1", p.WorkspaceID).Scan(&count, &limit); err == nil && count >= limit {
				err = errors.New("workspace user limit reached")
			}
			if err == nil {
				u.WorkspaceID, u.Email, u.Role = p.WorkspaceID, identity.Email, "user"
				if err = tx.QueryRow(r.Context(), "SELECT name FROM workspaces WHERE id=$1", p.WorkspaceID).Scan(&u.WorkspaceName); err == nil {
					u.Username = a.availableSSOUsername(r.Context(), tx, identity.Username, identity.Email)
					randomHash, hashErr := bcrypt.GenerateFromPassword([]byte(secure.Token()), bcrypt.DefaultCost)
					if hashErr != nil {
						err = hashErr
					} else {
						err = tx.QueryRow(r.Context(), `INSERT INTO users(workspace_id,username,email,email_verified_at,password_hash,role) VALUES($1,$2,$3,now(),$4,'user') RETURNING id,session_version`, p.WorkspaceID, u.Username, u.Email, string(randomHash)).Scan(&u.ID, &u.Version)
					}
				}
			}
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO external_identities(workspace_id,provider_id,user_id,subject,email,attributes,last_login_at) VALUES($1,$2,$3,$4,$5,$6,now())`, p.WorkspaceID, p.ID, u.ID, identity.Subject, identity.Email, identity.Attributes)
		}
	}
	if err != nil {
		a.ssoFailure(w, r)
		return
	}
	if _, err = tx.Exec(r.Context(), `UPDATE external_identities SET email=$1,attributes=$2,last_login_at=now() WHERE provider_id=$3 AND subject=$4`, identity.Email, identity.Attributes, p.ID, identity.Subject); err == nil {
		_, err = tx.Exec(r.Context(), "DELETE FROM sso_membership_grants WHERE provider_id=$1 AND user_id=$2", p.ID, u.ID)
	}
	if err == nil && len(identity.Groups) > 0 {
		_, err = tx.Exec(r.Context(), `INSERT INTO sso_membership_grants(workspace_id,provider_id,user_id,group_id,external_group,role)
SELECT m.workspace_id,m.provider_id,$3,m.group_id,m.external_group,m.membership_role
FROM identity_group_mappings m WHERE m.workspace_id=$1 AND m.provider_id=$2 AND m.external_group=ANY($4)`, p.WorkspaceID, p.ID, u.ID, identity.Groups)
	}
	if err == nil {
		err = tx.Commit(r.Context())
	}
	if err != nil {
		a.ssoFailure(w, r)
		return
	}
	_ = a.record(r.Context(), u.WorkspaceID, u.ID, u.Username, "auth.sso_login", fmt.Sprint(p.ID), map[string]any{"provider": p.Name, "protocol": p.Protocol, "groups": identity.Groups})
	if _, ok := a.establishSession(w, r, u); !ok {
		return
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) availableSSOUsername(ctx context.Context, tx pgx.Tx, preferred, email string) string {
	base := strings.TrimSpace(preferred)
	if base == "" {
		base = strings.Split(email, "@")[0]
	}
	base = regexp.MustCompile(`[^A-Za-z0-9._-]+`).ReplaceAllString(base, "-")
	base = strings.Trim(base, "-._")
	if len(base) < 3 {
		base = "sso-user"
	}
	if len(base) > 80 {
		base = base[:80]
	}
	for i := 0; i < 1000; i++ {
		candidate := base
		if i > 0 {
			candidate = fmt.Sprintf("%s-%d", base, i+1)
		}
		var exists bool
		if tx.QueryRow(ctx, "SELECT EXISTS(SELECT 1 FROM users WHERE lower(username)=lower($1))", candidate).Scan(&exists) == nil && !exists {
			return candidate
		}
	}
	return "sso-" + secure.Digest(email)[:12]
}

func firstClaim(claims map[string]any, path string) string {
	values := claimValues(claims, path)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func claimValues(claims map[string]any, path string) []string {
	var value any = claims
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		value = object[part]
	}
	switch typed := value.(type) {
	case string:
		if typed = strings.TrimSpace(typed); typed != "" {
			return []string{typed}
		}
	case []string:
		return typed
	case []any:
		out := []string{}
		for _, item := range typed {
			if text, ok := item.(string); ok && strings.TrimSpace(text) != "" {
				out = append(out, strings.TrimSpace(text))
			}
		}
		return out
	}
	return nil
}

func claimBool(claims map[string]any, path string) bool {
	var value any = claims
	for _, part := range strings.Split(path, ".") {
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		value = object[part]
	}
	if result, ok := value.(bool); ok {
		return result
	}
	return strings.EqualFold(fmt.Sprint(value), "true")
}

func (a *App) ssoFailure(w http.ResponseWriter, r *http.Request) {
	slog.Warn("SSO authentication failed", "path", r.URL.Path, "client_ip", a.clientIP(r))
	http.Redirect(w, r, "/?sso=failed", http.StatusSeeOther)
}
