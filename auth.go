package auth

// Authenticator is an interface for services providing authentication.
// It is used by Badge as a badge-scanner as a passport database.
// It is used by Login as a identity-affirming database.
type Authenticator interface {
	// Commands
	AddAuth(id interface{}, challenge interface{}) error
	RemoveAuth(id interface{}, challenge interface{}) error

	// Queries
	Auth(id interface{}, challenge interface{}) (bool, error)
	IDExists(id interface{}) (bool error)
}
