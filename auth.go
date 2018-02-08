package auth

import (
	"errors"

	"github.com/go-redis/redis"
)

// Authenticator is an interface for services providing authentication.
// It is used by Badge as a badge-scanner as a passport database.
// It is used by Login as a identity-affirming database.
type Authenticator interface {
	// Commands
	AddAuth(id interface{}, challenge interface{}) error
	RemoveAuth(id interface{}, challenge interface{}) error

	// Queries
	Auth(id interface{}, challenge interface{}) (bool, error)
	IDExists(id interface{}) (bool, error)
}

type Password struct {
	pwdDB redis.Client
}

func (p Password) AddAuth(id interface{}, challenge interface{}) error {
	s, ok := id.(string)
	if !ok {
		return errors.New("ID provided was not a string")
	}
	return p.pwdDB.Set(s, challenge, 0).Err()
}

func (p Password) RemoveAuth(id interface{}, challenge interface{}) error {
	s, ok := id.(string)
	if !ok {
		return errors.New("ID provided was not a string")
	}
	return p.pwdDB.Del(s).Err()
}

func (p Password) Auth(id interface{}, challenge interface{}) (bool, error) {
	s, ok := id.(string)
	if !ok {
		return false, errors.New("ID provided was not a string")
	}
	pwd, err := p.pwdDB.Get(s).Result()
	if err != nil {
		return false, err
	}
	if pwd == challenge {
		return true, nil
	}
	return false, errors.New("Bad challenge")
}

func (p Password) IDExists(id interface{}) (bool, error) {
	s, ok := id.(string)
	if !ok {
		return false, errors.New("ID provided was not a string")
	}
	pwd, err := p.pwdDB.Get(s).Result()
	if err != nil {
		return false, err
	}
	return pwd != "(nil)", nil
}
