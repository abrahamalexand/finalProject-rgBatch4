package repository

import (
	"a21hc3NpZ25tZW50/model"
	"time"

	"gorm.io/gorm"
)

type SessionRepository interface {
	AddSessions(session model.Session) error
	DeleteSession(token string) error
	UpdateSessions(session model.Session) error
	SessionAvailEmail(email string) (model.Session, error)
	SessionAvailToken(token string) (model.Session, error)
	TokenExpired(session model.Session) bool
}

type sessionsRepo struct {
	db *gorm.DB
}

func NewSessionsRepo(db *gorm.DB) *sessionsRepo {
	return &sessionsRepo{db}
}

func (u *sessionsRepo) AddSessions(session model.Session) error {
	return u.db.Create(&session).Error
}

func (u *sessionsRepo) DeleteSession(token string) error {
	return u.db.Where("token = ?", token).Delete(&model.Session{}).Error
}

func (u *sessionsRepo) UpdateSessions(session model.Session) error {
	return u.db.Where("email = ?", session.Email).Updates(&session).Error
}

func (u *sessionsRepo) SessionAvailEmail(email string) (model.Session, error) {
	var session model.Session
	err := u.db.Where("email = ?", email).First(&session).Error
	if err != nil {
		return model.Session{}, err
	}
	return session, nil
}

func (u *sessionsRepo) SessionAvailToken(token string) (model.Session, error) {
	var session model.Session
	err := u.db.Where("token = ?", token).First(&session).Error
	if err != nil {
		return model.Session{}, err
	}
	return session, nil
}

func (u *sessionsRepo) TokenValidity(token string) (model.Session, error) {
	session, err := u.SessionAvailToken(token)
	if err != nil {
		return model.Session{}, err
	}

	if u.TokenExpired(session) {
		err := u.DeleteSession(token)
		if err != nil {
			return model.Session{}, err
		}
		return model.Session{}, err
	}

	return session, nil
}

func (u *sessionsRepo) TokenExpired(session model.Session) bool {
	return session.Expiry.Before(time.Now())
}
