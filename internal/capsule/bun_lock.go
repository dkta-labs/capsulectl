package capsule

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

type bunLock struct {
	LockfileVersion int                        `json:"lockfileVersion"`
	Packages        map[string]json.RawMessage `json:"packages"`
}

func ParseDependencyLock(filename string) ([]Package, error) {
	switch filepathBase := strings.ToLower(filepathBase(filename)); filepathBase {
	case "package-lock.json":
		return ParsePackageLock(filename)
	case "bun.lock":
		return ParseBunLock(filename)
	case "bun.lockb":
		return nil, errors.New("binary bun.lockb is unsupported; migrate to the reviewable text bun.lock format")
	default:
		return nil, fmt.Errorf("unsupported dependency lockfile: %s", filepathBase)
	}
}

func filepathBase(filename string) string {
	lastSlash := strings.LastIndexAny(filename, `/\\`)
	if lastSlash >= 0 {
		return filename[lastSlash+1:]
	}
	return filename
}

func ParseBunLock(filename string) ([]Package, error) {
	contents, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	jsonContents, err := normalizeJSONC(contents)
	if err != nil {
		return nil, fmt.Errorf("decode bun.lock: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(jsonContents))
	var lock bunLock
	if err := decoder.Decode(&lock); err != nil {
		return nil, fmt.Errorf("decode bun.lock: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode bun.lock: trailing JSON value")
	}
	if lock.LockfileVersion < 0 || lock.LockfileVersion > 1 || lock.Packages == nil {
		return nil, errors.New("bun.lock version 0 or 1 with a packages object is required")
	}
	packages := make([]Package, 0, len(lock.Packages))
	for key, raw := range lock.Packages {
		var fields []json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || len(fields) == 0 {
			return nil, fmt.Errorf("invalid bun.lock package entry %q", key)
		}
		var resolution string
		if err := json.Unmarshal(fields[0], &resolution); err != nil || resolution == "" {
			return nil, fmt.Errorf("invalid bun.lock package resolution %q", key)
		}
		if strings.Contains(resolution, "@workspace:") || strings.HasPrefix(resolution, "workspace:") {
			continue
		}
		name, version, ok := splitRegistryResolution(resolution)
		if !ok {
			return nil, fmt.Errorf("bun.lock contains non-registry or non-exact resolution %q", resolution)
		}
		integrity := ""
		if len(fields) >= 4 {
			_ = json.Unmarshal(fields[3], &integrity)
		}
		if integrity == "" || !strings.HasPrefix(integrity, "sha512-") {
			return nil, fmt.Errorf("bun.lock package %s@%s lacks sha512 integrity", name, version)
		}
		packages = append(packages, Package{Name: name, Version: version, Integrity: integrity})
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].Version < packages[j].Version
		}
		return packages[i].Name < packages[j].Name
	})
	return packages, nil
}

func splitRegistryResolution(resolution string) (string, string, bool) {
	separator := strings.LastIndex(resolution, "@")
	if separator <= 0 {
		return "", "", false
	}
	name, version := resolution[:separator], resolution[separator+1:]
	if !npmPackageName.MatchString(name) || !exactPackageVersion.MatchString(version) {
		return "", "", false
	}
	return name, version, true
}

func normalizeJSONC(input []byte) ([]byte, error) {
	withoutComments := make([]byte, 0, len(input))
	inString, escaped := false, false
	for index := 0; index < len(input); index++ {
		current := input[index]
		if inString {
			withoutComments = append(withoutComments, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			withoutComments = append(withoutComments, current)
			continue
		}
		if current == '/' && index+1 < len(input) && input[index+1] == '/' {
			index += 2
			for index < len(input) && input[index] != '\n' {
				index++
			}
			if index < len(input) {
				withoutComments = append(withoutComments, '\n')
			}
			continue
		}
		if current == '/' && index+1 < len(input) && input[index+1] == '*' {
			index += 2
			closed := false
			for index < len(input) {
				if input[index] == '\n' {
					withoutComments = append(withoutComments, '\n')
				}
				if input[index] == '*' && index+1 < len(input) && input[index+1] == '/' {
					index++
					closed = true
					break
				}
				index++
			}
			if !closed {
				return nil, errors.New("unterminated block comment")
			}
			continue
		}
		withoutComments = append(withoutComments, current)
	}
	if inString {
		return nil, errors.New("unterminated string")
	}

	output := make([]byte, 0, len(withoutComments))
	inString, escaped = false, false
	for index := 0; index < len(withoutComments); index++ {
		current := withoutComments[index]
		if inString {
			output = append(output, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			output = append(output, current)
			continue
		}
		if current == ',' {
			next := index + 1
			for next < len(withoutComments) && (withoutComments[next] == ' ' || withoutComments[next] == '\t' || withoutComments[next] == '\r' || withoutComments[next] == '\n') {
				next++
			}
			if next < len(withoutComments) && (withoutComments[next] == '}' || withoutComments[next] == ']') {
				continue
			}
		}
		output = append(output, current)
	}
	return output, nil
}
