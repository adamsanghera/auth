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

type RedisPasswordAuth struct {
	pwdDB *redis.Client
}

func NewLocalPasswordAuth(dbNum int) (RedisPasswordAuth, error) {
	pwdauth := RedisPasswordAuth{
		pwdDB: redis.NewClient(&redis.Options{
			Addr:     "localhost" + ":" + "6379",
			Password: "",    // no password set
			DB:       dbNum, // use default DB
		}),
	}
	return pwdauth, pwdauth.pwdDB.Ping().Err()
}

func (p RedisPasswordAuth) AddAuth(id interface{}, challenge interface{}) error {
	s, ok := id.(string)
	if !ok {
		return errors.New("ID provided was not a string")
	}
	return p.pwdDB.Set(s, challenge, 0).Err()
}

func (p RedisPasswordAuth) RemoveAuth(id interface{}, challenge interface{}) error {
	s, ok := id.(string)
	if !ok {
		return errors.New("ID provided was not a string")
	}

	_, err := p.Auth(id, challenge)
	if err != nil {
		return err
	}
	return p.pwdDB.Del(s).Err()
}

func (p RedisPasswordAuth) Auth(id interface{}, challenge interface{}) (bool, error) {
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

func (p RedisPasswordAuth) IDExists(id interface{}) (bool, error) {
	s, ok := id.(string)
	if !ok {
		return false, errors.New("ID provided was not a string")
	}
	_, err := p.pwdDB.Get(s).Result()
	if err != nil {
		if err.Error() == "redis: nil" {
			return false, nil
		}
		return false, err
	}
	return true, nil
}
