/*
Copyright Hitachi, Ltd. 2020 All Rights Reserved.

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

package immutil

import (
	"os"
	"os/exec"
	"fmt"
)

func CopyFile(srcFile, dstFile string, perm os.FileMode) error {
	srcBuf, err := os.ReadFile(srcFile)
	if err != nil {
		return err
	}

	err = os.WriteFile(dstFile, srcBuf, perm)
	if err != nil {
		return err
	}

	return nil
}

func CopyTemplate(templateDir, dstDir string) error {
	copyCmd := "/usr/bin/find -print | cpio -o | cpio -idu -D "
	
	cmd := exec.Command("/bin/sh", "-c", copyCmd + dstDir)
	cmd.Dir = templateDir // template source
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not copy template files: %s", err)
	}

	return nil // success
}
