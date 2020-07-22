package immutil

import (
	"io/ioutil"
	"os"
	"os/exec"
	"fmt"
)

func CopyFile(srcFile, dstFile string, perm os.FileMode) error {
	srcBuf, err := ioutil.ReadFile(srcFile)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dstFile, srcBuf, perm)
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
