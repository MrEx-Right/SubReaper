package discovery

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/MrEx-Right/SubReaper/assets"
)

func sorted(s []string) []string {
	out := append([]string(nil), s...)
	sort.Strings(out)
	return out
}

func TestHostsInRapidDNSHTML(t *testing.T) {
	html := `<table><tr><td>1</td><td>api.example.com</td><td>192.0.2.1</td></tr>
<tr><td>2</td><td>WWW.Example.com</td><td>CNAME</td></tr>
<tr><td>3</td><td>example.com.evil.net</td></tr>
<tr><td>4</td><td>notexample.com</td></tr>
<meta name="description" content="Found 2 subdomains for example.com on RapidDNS"></table>`
	got := sorted(hostsIn("example.com", html))
	want := []string{"api.example.com", "www.example.com"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseWayback(t *testing.T) {
	in := "https://a.example.com/x?y=1\nhttp://B.example.com:8080/\nexample.com/robots.txt\nhttps://other.org/\n"
	got, err := parseWayback("example.com", strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.example.com", "b.example.com", "example.com"}
	if strings.Join(sorted(got), ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseHackertarget(t *testing.T) {
	got := parseHackertarget("example.com", "a.example.com,192.0.2.1\nb.example.com,192.0.2.2\n")
	if len(got) != 2 {
		t.Fatalf("got %v", got)
	}
}

func TestFilterSubdomainsRejectsJunk(t *testing.T) {
	got := filterSubdomains("example.com", []string{"*.example.com", "a b.example.com", "x.example.com.", "x.example.com", "evil-example.com"})
	if strings.Join(got, ",") != "example.com,x.example.com" {
		t.Fatalf("got %v", got)
	}
}

func TestEmbeddedWordlist(t *testing.T) {
	got, err := ParseWordlist(bytes.NewReader(assets.DefaultWordlist), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) < 100 {
		t.Fatalf("embedded wordlist yielded only %d candidates", len(got))
	}
	for _, c := range got {
		if !strings.HasSuffix(c, ".example.com") {
			t.Fatalf("bad candidate %q", c)
		}
	}
}

func TestPermutationsForDeepTarget(t *testing.T) {
	perms := GeneratePermutations([]string{"api.dev.example.com"}, "dev.example.com")
	if len(perms) == 0 {
		t.Fatal("permutations must work when the target is itself a subdomain")
	}
}
