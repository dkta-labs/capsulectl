package capsule

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const maxFeedBytes = 16 << 20

type FeedFetcher interface {
	Fetch(context.Context, string) ([]byte, error)
}

type HTTPFeedFetcher struct {
	Client *http.Client
}

func NewHTTPFeedFetcher(timeout time.Duration) HTTPFeedFetcher {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return HTTPFeedFetcher{Client: &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(request *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many feed redirects")
			}
			if request.URL.Scheme != "https" || request.URL.Host != via[0].URL.Host {
				return errors.New("deny feed redirect changed origin")
			}
			return nil
		},
	}}
}

func (fetcher HTTPFeedFetcher) Fetch(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid HTTPS deny feed: %s", rawURL)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "text/csv")
	response, err := fetcher.Client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("deny feed returned HTTP %d", response.StatusCode)
	}
	contents, err := io.ReadAll(io.LimitReader(response.Body, maxFeedBytes+1))
	if err != nil {
		return nil, err
	}
	if len(contents) > maxFeedBytes {
		return nil, errors.New("deny feed exceeds 16 MiB")
	}
	return contents, nil
}

type affectedPackage struct {
	Name    string
	Version string
}

func CheckFeeds(ctx context.Context, fetcher FeedFetcher, feeds []string, packages []Package, now time.Time) ([]FeedEvidence, error) {
	packageSet := make(map[affectedPackage]bool, len(packages))
	for _, pkg := range packages {
		packageSet[affectedPackage{Name: pkg.Name, Version: pkg.Version}] = true
	}
	evidence := make([]FeedEvidence, 0, len(feeds))
	for _, feed := range feeds {
		contents, err := fetcher.Fetch(ctx, feed)
		if err != nil {
			return nil, fmt.Errorf("fetch deny feed %s: %w", feed, err)
		}
		affected, err := parseSocketCSV(contents)
		if err != nil {
			return nil, fmt.Errorf("parse deny feed %s: %w", feed, err)
		}
		var matches []string
		for _, item := range affected {
			if packageSet[item] {
				matches = append(matches, item.Name+"@"+item.Version)
			}
		}
		sort.Strings(matches)
		if len(matches) > 0 {
			return nil, fmt.Errorf("deny feed blocks dependency artifacts: %s", strings.Join(matches, ", "))
		}
		digest := sha256.Sum256(contents)
		evidence = append(evidence, FeedEvidence{
			URL:       feed,
			SHA256:    hex.EncodeToString(digest[:]),
			Artifacts: len(affected),
			CheckedAt: now.UTC().Format(time.RFC3339),
		})
	}
	return evidence, nil
}

func parseSocketCSV(contents []byte) ([]affectedPackage, error) {
	reader := csv.NewReader(bytes.NewReader(contents))
	reader.FieldsPerRecord = -1
	header, err := reader.Read()
	if err != nil {
		return nil, err
	}
	columns := map[string]int{}
	for index, name := range header {
		columns[name] = index
	}
	for _, required := range []string{"Ecosystem", "Namespace", "Name", "Version"} {
		if _, ok := columns[required]; !ok {
			return nil, fmt.Errorf("missing required column %s", required)
		}
	}
	maxColumn := 0
	for _, index := range columns {
		if index > maxColumn {
			maxColumn = index
		}
	}
	var affected []affectedPackage
	for {
		row, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(row) <= maxColumn || strings.ToLower(strings.TrimSpace(row[columns["Ecosystem"]])) != "npm" {
			continue
		}
		namespace := strings.TrimSpace(row[columns["Namespace"]])
		name := strings.TrimSpace(row[columns["Name"]])
		version := strings.TrimSpace(row[columns["Version"]])
		if namespace != "" {
			name = "@" + strings.TrimPrefix(namespace, "@") + "/" + name
		}
		if name != "" && version != "" {
			affected = append(affected, affectedPackage{Name: name, Version: version})
		}
	}
	return affected, nil
}
