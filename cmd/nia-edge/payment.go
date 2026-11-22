package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/GetKlaros/nia-edge/internal/near"
	"github.com/GetKlaros/nia-edge/internal/niaclient"
	"github.com/GetKlaros/nia-edge/internal/paymcp"
	"github.com/GetKlaros/nia-edge/internal/state"
)

// paymentAccount is the agent's payment key and the account Nia linked to it.
type paymentAccount struct {
	mu      sync.Mutex
	key     ed25519.PrivateKey
	account string
}

func (p *paymentAccount) get() (paymcp.Account, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.account == "" {
		return paymcp.Account{}, errors.New("no payment account")
	}
	return paymcp.Account{ID: p.account, Key: p.key}, nil
}

// paymentKey is the agent's payment key from the state file, made and kept
// there first if there is none. lock serializes the state file's writers.
func paymentKey(path string, lock *sync.Mutex) (*paymentAccount, error) {
	lock.Lock()
	defer lock.Unlock()
	current, err := state.Load(path)
	if err != nil {
		return nil, err
	}
	if current.Payment == nil {
		seed := make([]byte, ed25519.SeedSize)
		if _, err := rand.Read(seed); err != nil {
			return nil, err
		}
		current.Payment = &state.Payment{Seed: base64.StdEncoding.EncodeToString(seed)}
		if err := state.Save(path, current); err != nil {
			return nil, err
		}
	}
	seed, err := base64.StdEncoding.DecodeString(current.Payment.Seed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("the payment key in the state file cannot be read")
	}
	account := current.Payment.Account
	if account != "" && !near.ValidAccount(account) {
		account = ""
	}
	return &paymentAccount{key: ed25519.NewKeyFromSeed(seed), account: account}, nil
}

// reportPayment tells Nia the payment public key until Nia names the
// account linked to it, and keeps that account in the state file.
func reportPayment(ctx context.Context, client *niaclient.Client, key, path string, lock *sync.Mutex, p *paymentAccount, logger *slog.Logger) {
	public := near.PublicKey(p.key.Public().(ed25519.PublicKey))
	for {
		account, err := client.PaymentKey(ctx, key, public)
		switch {
		case err != nil:
			logger.Warn("the payment key could not be reported to Nia", "error", err)
		case account != "" && near.ValidAccount(account):
			p.mu.Lock()
			changed := p.account != account
			p.account = account
			p.mu.Unlock()
			if changed {
				lock.Lock()
				current, err := state.Load(path)
				if err == nil && current.Payment != nil {
					current.Payment.Account = account
					err = state.Save(path, current)
				}
				lock.Unlock()
				if err != nil {
					logger.Warn("the payment account could not be kept in the state file", "error", err)
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(10 * time.Minute):
		}
	}
}

// niaVisas asks Nia for visas with the machine's key.
type niaVisas struct {
	client            *niaclient.Client
	key, session, run string
}

func (v niaVisas) Visa(ctx context.Context, tool string, arguments json.RawMessage, opID string) (*paymcp.VisaAnswer, error) {
	raw, err := v.client.Visa(ctx, v.key, v.session, v.run, tool, arguments, opID)
	if err != nil {
		return nil, err
	}
	var answer paymcp.VisaAnswer
	if err := json.Unmarshal(raw, &answer); err != nil {
		return nil, errors.New("Nia's visa cannot be read")
	}
	return &answer, nil
}

// niaPlans asks Nia which vault operation a payment is.
type niaPlans struct {
	client *niaclient.Client
	key    string
}

func (p niaPlans) Plan(ctx context.Context, arguments json.RawMessage) (*paymcp.Payment, error) {
	raw, err := p.client.PaymentPlan(ctx, p.key, arguments)
	if err != nil {
		var refused *niaclient.Refused
		if errors.As(err, &refused) && refused.Message != "" {
			return nil, errors.New(refused.Message)
		}
		return nil, err
	}
	var plan paymcp.Payment
	if err := json.Unmarshal(raw, &plan); err != nil {
		return nil, errors.New("Nia's plan cannot be read")
	}
	return &plan, nil
}
