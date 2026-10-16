package providers

import (
	"context"
	"errors"
	"testing"
)

func TestS3Patterns(t *testing.T) {
	reg := DefaultRegistry()
	s3 := reg.Get("AWS S3")
	for _, c := range []string{
		"bucket.s3.amazonaws.com",
		"my.dotted.bucket.s3.amazonaws.com",
		"bucket.s3-website-us-east-1.amazonaws.com",
		"bucket.s3-website.eu-central-1.amazonaws.com",
		"bucket.s3.us-east-2.amazonaws.com",
	} {
		if s3.MatchCNAME(c) == "" {
			t.Errorf("%s should match AWS S3", c)
		}
	}
	if s3.MatchCNAME("ec2-1-2-3-4.compute.amazonaws.com") != "" {
		t.Error("EC2 hostnames must not match AWS S3")
	}
}

func TestNXClaimNeverTreatsErrorsAsClaimable(t *testing.T) {
	env := &CheckEnv{IsNXDOMAIN: func(ctx context.Context, host string) (bool, error) {
		return false, errors.New("timeout")
	}}
	ok, err := nxClaim(".azurewebsites.net")(context.Background(), env, "x.azurewebsites.net")
	if ok || err == nil {
		t.Fatalf("ok=%v err=%v, want false with error", ok, err)
	}

	env.IsNXDOMAIN = func(ctx context.Context, host string) (bool, error) { return true, nil }
	ok, err = nxClaim(".azurewebsites.net")(context.Background(), env, "x.azurewebsites.net")
	if !ok || err != nil {
		t.Fatalf("ok=%v err=%v, want true", ok, err)
	}
	ok, _ = nxClaim(".azurewebsites.net")(context.Background(), env, "x.example.net")
	if ok {
		t.Fatal("suffix outside the claimable namespace must not be claimable")
	}
}

func TestEveryProviderHasStatusAndCNAME(t *testing.T) {
	for _, p := range DefaultRegistry().All() {
		if p.Status == "" {
			t.Errorf("%s has no status", p.Name)
		}
		if len(p.CNAMESuffixes) == 0 && len(p.CNAMEPatterns) == 0 {
			t.Errorf("%s has no CNAME matcher", p.Name)
		}
	}
}
