package capsule

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

const maxRuntimeSourceFiles = 200000
const maxRuntimeSourceBytes int64 = 2 << 30

func prepareRuntimeSource(sourceRoot string) (string, error) {
	stageRoot, err := runtimeSourceStageRoot(sourceRoot)
	if err != nil {
		return "", err
	}
	return prepareRuntimeSourceAt(sourceRoot, stageRoot)
}

func runtimeSourceStageRoot(sourceRoot string) (string, error) {
	home := ""
	if runtime.GOOS == "darwin" {
		var err error
		home, err = os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve daemon-visible runtime staging root: %w", err)
		}
	}
	return runtimeSourceStageRootFor(sourceRoot, runtime.GOOS, home)
}

func runtimeSourceStageRootFor(sourceRoot, operatingSystem, home string) (string, error) {
	if operatingSystem != "darwin" {
		stageRoot := filepath.Dir(sourceRoot)
		if err := validateRuntimeStageRoot(sourceRoot, stageRoot); err != nil {
			return "", err
		}
		return stageRoot, nil
	}
	homeInfo, err := os.Stat(home)
	if err != nil {
		return "", fmt.Errorf("inspect daemon-visible runtime staging root: %w", err)
	}
	if !homeInfo.IsDir() {
		return "", errors.New("daemon-visible runtime staging root is not a directory")
	}
	if err := validateRuntimeStageRoot(sourceRoot, home); err != nil {
		return "", err
	}
	return home, nil
}

func validateRuntimeStageRoot(sourceRoot, stageRoot string) error {
	sourceAbsolute, err := filepath.Abs(sourceRoot)
	if err != nil {
		return err
	}
	stageAbsolute, err := filepath.Abs(stageRoot)
	if err != nil {
		return err
	}
	relative, err := filepath.Rel(sourceAbsolute, stageAbsolute)
	if err != nil {
		return err
	}
	if relative == "." || (relative != ".." && !hasParentPrefix(relative)) {
		return errors.New("daemon-visible runtime staging root must be outside the source root")
	}
	return nil
}

func hasParentPrefix(path string) bool {
	return len(path) >= 3 && path[:3] == ".."+string(filepath.Separator)
}

func prepareRuntimeSourceAt(sourceRoot, stageRoot string) (string, error) {
	if err := validateRuntimeStageRoot(sourceRoot, stageRoot); err != nil {
		return "", err
	}
	stage, err := os.MkdirTemp(stageRoot, ".capsulectl-source-")
	if err != nil {
		return "", err
	}
	if err := os.Chmod(stage, 0o755); err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	files := 0
	var bytesCopied int64
	if err := copyRuntimeDirectory(sourceRoot, stage, &files, &bytesCopied); err != nil {
		os.RemoveAll(stage)
		return "", err
	}
	return stage, nil
}

func copyRuntimeDirectory(source, target string, files *int, bytesCopied *int64) error {
	entries, err := os.ReadDir(source)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == ".git" || entry.Name() == "node_modules" {
			continue
		}
		*files++
		if *files > maxRuntimeSourceFiles {
			return errors.New("runtime source exceeds file-count limit")
		}
		sourcePath := filepath.Join(source, entry.Name())
		targetPath := filepath.Join(target, entry.Name())
		info, err := os.Lstat(sourcePath)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("runtime source symlinks require explicit review: %s", sourcePath)
		}
		if info.IsDir() {
			if err := os.Mkdir(targetPath, 0o755); err != nil {
				return err
			}
			if err := copyRuntimeDirectory(sourcePath, targetPath, files, bytesCopied); err != nil {
				return err
			}
			continue
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("runtime source contains a non-regular file: %s", sourcePath)
		}
		*bytesCopied += info.Size()
		if *bytesCopied > maxRuntimeSourceBytes {
			return errors.New("runtime source exceeds size limit")
		}
		if err := copyRuntimeFile(sourcePath, targetPath, info); err != nil {
			return err
		}
	}
	return nil
}

func copyRuntimeFile(source, target string, before os.FileInfo) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	mode := before.Mode().Perm() & 0o111
	mode |= 0o444
	output, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	after, err := input.Stat()
	if err != nil {
		return err
	}
	if before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) || before.Mode() != after.Mode() {
		return fmt.Errorf("runtime source changed while staging: %s", source)
	}
	return nil
}
