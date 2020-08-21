/*
Copyright 2020 Google Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package util

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fsnotify/fsnotify"

	"github.com/coreos/etcd/pkg/fileutil"
)

// AtomicWrite writes to a temporary file in the same directory then renames the temporary file.
func AtomicWrite(path string, data []byte, mode os.FileMode) (err error) {
	tmpFile, err := ioutil.TempFile(filepath.Dir(path), filepath.Base(path)+".tmp.")
	if err != nil {
		return
	}
	defer func() {
		if fileutil.Exist(tmpFile.Name()) {
			if rmErr := os.Remove(tmpFile.Name()); rmErr != nil {
				if err != nil {
					err = fmt.Errorf("%w; %s", err, rmErr.Error())
				} else {
					err = rmErr
				}
			}
		}
	}()

	if err = os.Chmod(tmpFile.Name(), mode); err != nil {
		return
	}

	_, err = tmpFile.Write(data)
	if err != nil {
		if closeErr := tmpFile.Close(); closeErr != nil {
			err = fmt.Errorf("%w; %s", err, closeErr.Error())
		}
		return
	}
	if err = tmpFile.Close(); err != nil {
		return
	}

	err = os.Rename(tmpFile.Name(), path)
	return
}

// Creates a file watcher that watches for any changes to the directory
func CreateFileWatcher(dir string) (watcher *fsnotify.Watcher, fileModified chan bool, errChan chan error, err error) {
	watcher, err = fsnotify.NewWatcher()
	if err != nil {
		return
	}

	fileModified, errChan = make(chan bool), make(chan error)
	go watchFiles(watcher, fileModified, errChan)

	if err = watcher.Add(dir); err != nil {
		if closeErr := watcher.Close(); closeErr != nil {
			err = fmt.Errorf("%w; %s", err, closeErr.Error())
		}
		return nil, nil, nil, err
	}

	return
}

func watchFiles(watcher *fsnotify.Watcher, fileModified chan bool, errChan chan error) {
	for {
		select {
		case _, ok := <-watcher.Events:
			if !ok {
				return
			}
			fileModified <- true
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			errChan <- err
		}
	}
}
