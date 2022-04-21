/*
Copyright Hitachi, Ltd. 2022 All Rights Reserved.

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

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"strings"
	filepath "path"
	"io"
	"io/fs"
	"net/http"
	"encoding/hex"
	"encoding/json"
	"crypto/rand"
	"crypto/sha256"
	"archive/tar"
	"compress/gzip"
	"sync/atomic"
	"time"	
)

var pluginCmd *exec.Cmd
var pluginCmdLock = int32(0)
var waitPluginCmdF = int32(0)

var expectImg string
var expectCont string
const (
	expectCmd = "chaincode"
	expectExtractDir = "/etc/hyperledger/fabric"
	pluginCmdName = "/var/lib/hlRsyslog"
)

func lockPluginCmd() bool {
	for i := 0; ; i++ {
		if atomic.CompareAndSwapInt32(&pluginCmdLock, 0, 1) == true {
			return true // success
		}

		if i == 3 {
			return false  // failure
		}
		time.Sleep(time.Second)
	}
	return false  // failure
}

func unlockPluginCmd() {
	pluginCmdLock = 0
}

func randHexStr(num int) string {
	availStr := []byte("abcdef01234567")
	randStr := ""

	b := make([]byte, num)
	rand.Read(b)

	for i := 0; i < num; i++ {
		randStr += string(availStr[int(b[i])%len(availStr)])
	}

	return randStr
}

func responseMsg(w http.ResponseWriter, msg string) {
	rspScheme := &struct{
		Message string `json:"message"`
	}{
		Message: msg,
	}
	rspData, _ := json.Marshal(rspScheme)
	w.Write(rspData)
}

func nopHandler(w http.ResponseWriter, req *http.Request) {
	log.Printf("not implemented request\n")
	log.Printf("URL: %s\n", req.URL)
	log.Printf("Header: %v\n", req.Header)

	if req.Body == nil {
		return
	}
	defer req.Body.Close()
	
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("got an error: %s\n", err)
		return
	}
	
	log.Printf("Body:\n%s\n", hex.Dump(reqBody))
}

func createContainer(w http.ResponseWriter, req *http.Request) {
	if req.Body == nil{
		log.Printf("unexpected request\n")
		w.WriteHeader(http.StatusBadRequest)
		responseMsg(w, "the request body is null")
		return
	}
	
	reqBody, err := io.ReadAll(req.Body)
	if err != nil {
		log.Printf("got an error: %s\n", err)
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "could not read the request body: " + err.Error() )
		return
	}

	param := &struct{
		Env []string
		Cmd []string
		Image string
	}{}
	json.Unmarshal(reqBody, param)
	log.Printf("Env: %v\n", param.Env)
	log.Printf("Cmd: %v\n", param.Cmd)
	log.Printf("Image: %s\n", param.Image)

	if param.Image != expectImg {
		log.Printf("unexpected image name: %s\n", param.Image)
		w.WriteHeader(http.StatusNotFound)
		responseMsg(w, "no such image: " + param.Image)
		return
	}
	
	if param.Cmd[0] != expectCmd {
		log.Printf("unexpected command: %s\n", param.Image)
		w.WriteHeader(http.StatusBadRequest)
		responseMsg(w, "unexpected command: " + param.Cmd[0])
		return
	}

	if lockPluginCmd() == false {
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "another command is running")
		return
	}
	defer unlockPluginCmd()
	
	pluginCmd = exec.Command(pluginCmdName, param.Cmd[1:]...)
	pluginCmd.Env = param.Env
	pluginCmd.Stdout = os.Stdout
	pluginCmd.Stderr = os.Stderr

	rspScheme := &struct{
		Id string
		Warnings []string
	}{
		Id: randHexStr(64),
	}
	rspData, _ := json.Marshal(rspScheme)
	log.Printf("created id=%s\n", rspScheme.Id)

	w.WriteHeader(http.StatusCreated) // success
	w.Write(rspData)
}

func containerOp(w http.ResponseWriter, req *http.Request) {
	path := strings.TrimPrefix(req.URL.Path, "/containers/")

	var retErr error
	defer func() {
		if retErr== nil {
			return
		}
		log.Printf("%s\n", retErr)
		
		if req.Body == nil {
			return
		}
		
		io.ReadAll(req.Body)
		req.Body.Close()
	}()

	idAndOp := strings.SplitN(path, "/", 2)
	opName := "remove"
	if len(idAndOp) ==  1 {
		if req.Method !=  http.MethodDelete {
			retErr = fmt.Errorf("unexpected request: method=%s: %v", req.Method, idAndOp)
			w.WriteHeader(http.StatusBadRequest)
			responseMsg(w, retErr.Error())
			return
		}
	}
	if len(idAndOp) == 2 {
		opName = idAndOp[1]
	}
	
	containerName := idAndOp[0]
	log.Printf("containerName=%s\n", containerName)

	if containerName != expectCont {
		retErr = fmt.Errorf("unexepcted container name: %s", containerName)
		w.WriteHeader(http.StatusNotFound)
		responseMsg(w, "no such container: " + containerName)
		return
	}

	log.Printf("OP name=%s\n", opName)
	switch opName {
	case "archive":
		retErr = extractFile(w, req)
		return
	case "start":
		retErr = startContainer(w, req)
		return
	case "stop":
		retErr = stopContainer(w, req)
		return
	case "kill":
		retErr = killContainer(w, req)
		return
	case "remove":
		retErr = removeContainer(w, req)
		return
	case "wait":
		retErr = waitContainer(w, req)
		return
	default:
		retErr = fmt.Errorf("not implemented request: " + opName)
		return
	}
}

func extractFile(w http.ResponseWriter, req *http.Request) (retErr error) {
	extractDir := req.URL.Query().Get("path")
	log.Printf("extracting directory=%s\n", extractDir)

	var buf io.Reader
	buf = req.Body
		
	compressAlgo := req.Header.Get("Accept-Encoding")
	if compressAlgo == "gzip" {
		gzipReader, err := gzip.NewReader(req.Body)
		if err != nil {
			retErr = fmt.Errorf("failed to create a reader for gzip: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			responseMsg(w, retErr.Error())
			return
		}
		buf = gzipReader
	}

	tarReader := tar.NewReader(buf)
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			err = nil
			break
		}

		if err != nil {
			retErr = fmt.Errorf("failed to read a tar: %s", err)
			w.WriteHeader(http.StatusInternalServerError)
			responseMsg(w, retErr.Error())
			return
		}

		dirName := ""
		dirFileMode := fs.FileMode(0755)
		regularFileF := (header.Typeflag == tar.TypeReg)
		if header.Typeflag == tar.TypeDir {
			dirName = header.Name
			dirFileMode = fs.FileMode(header.Mode)
		}
		
		if regularFileF {
			dirName = filepath.Dir(header.Name)
		}

		if dirName == "" || dirName != expectExtractDir {
			continue
		}

		_, err = os.Stat(dirName)
		if err != nil {
			log.Printf("create %s directory: %s\n", dirName, err)
			err = os.MkdirAll(dirName, dirFileMode)
			if err != nil {
				retErr = fmt.Errorf("failed to create %s directory: %s", dirName, err)
				w.WriteHeader(http.StatusForbidden)
				responseMsg(w, retErr.Error())
				return
			}
		}

		if ! regularFileF {
			continue
		}
		
		log.Printf("create %s\n", header.Name)
		wfile, err := os.OpenFile(header.Name, os.O_RDWR|os.O_CREATE, fs.FileMode(header.Mode))
		if err != nil {
			retErr = fmt.Errorf("failed to create %s: %s", header.Name, err)
			w.WriteHeader(http.StatusForbidden)
			responseMsg(w, retErr.Error())			
			return
		}

		var readN int
		readData := make([]byte, 256)
		for err == nil {
			readN, err = tarReader.Read(readData)
			wfile.Write(readData[:readN])
		}
		wfile.Close()
		
		if err != io.EOF {
			retErr = fmt.Errorf("failed to read %s: %s", header.Name, err)
			w.WriteHeader(http.StatusForbidden)
			responseMsg(w, retErr.Error())			
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	return
}

func stopContainer(w http.ResponseWriter, req *http.Request) (retErr error) {
	if lockPluginCmd() == false {
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "another request is running")
		return
	}
	defer unlockPluginCmd()
	
	if pluginCmd == nil || pluginCmd.Process == nil {
		w.WriteHeader(http.StatusNotModified) // container already stopped
		return
	}

	log.Printf("stop a process: kill pid=%d\n", pluginCmd.Process.Pid)
	pluginCmd.Process.Kill()
	pluginCmd.Wait()
	pluginCmd.Process = nil	
	
	w.WriteHeader(http.StatusNoContent) // success
	return
}

func killContainer(w http.ResponseWriter, req *http.Request) (retErr error) {
	if lockPluginCmd() == false {
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "another request is running")
		return
	}
	defer unlockPluginCmd()
	
	if pluginCmd == nil || pluginCmd.Process == nil {
		w.WriteHeader(http.StatusConflict) // container is not running
		responseMsg(w, "container is not running")
		return
	}

	log.Printf("kill a process: kill pid=%d\n", pluginCmd.Process.Pid)	
	pluginCmd.Process.Signal(syscall.SIGKILL)
	pluginCmd.Wait()
	pluginCmd.Process = nil
	w.WriteHeader(http.StatusNoContent) // success
	return
}

func startContainer(w http.ResponseWriter, req *http.Request) (retErr error) {
	if lockPluginCmd() == false {
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "another request is running")
		return
	}
	defer unlockPluginCmd()
	
	if pluginCmd == nil {
		w.WriteHeader(http.StatusNotFound)
		responseMsg(w, "no such container")
		return
	}

	if pluginCmd.Process != nil {
		err := pluginCmd.Process.Signal(syscall.Signal(0))
		if err != nil {
			w.WriteHeader(http.StatusNotModified) // container already started
			return
		}

		pluginCmd.Process = nil
	}

	err := pluginCmd.Start()
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		retErr = fmt.Errorf("failed to start a command: %s", err)
		responseMsg(w, retErr.Error())
		return
	}

	log.Printf("started the plugin command\n")
	w.WriteHeader(http.StatusNoContent) // success
	return
}

func removeContainer(w http.ResponseWriter, req *http.Request) (retErr error) {
	forceF := req.URL.Query().Get("force")

	if lockPluginCmd() == false {
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "another request is running")
		return		
	}
	defer unlockPluginCmd()
	
	if pluginCmd != nil && pluginCmd.Process != nil {
		if forceF != "1" {
			w.WriteHeader(http.StatusConflict)
			responseMsg(w, "container is running")
			return
		}

		pluginCmd.Process.Kill()
		pluginCmd.Wait()		
	}

	log.Printf("remove a process context\n")
	pluginCmd = nil
	w.WriteHeader(http.StatusNoContent) // success
	return
}

func dockerVersion(w http.ResponseWriter, req *http.Request) {
	type PlatformS struct{ Name string }
	type ComponentsS struct{
		Name string
		Version string
		Details []string
	}
	rspScheme := &struct{
		Platform PlatformS
		Components []ComponentsS
		ApiVersion string
		MinAPIVersion string
		GitCommit string
		GoVersion string
		Os string
		Arch string
		KernelVersion string
		Experimental bool
		BuildTime string
	}{
		Platform: PlatformS{
			Name: "linux/amd64",
		},
		Components: []ComponentsS{ComponentsS{
			Name: "dockerHandler",
			Version: "1",
		}, },
		ApiVersion: "1.40", // fake
		MinAPIVersion: "1.12", // fake
		GoVersion: "go1.17.6",
		Os: "linux",
		Arch: "amd64",
	}

	rspData, _ := json.Marshal(rspScheme)

	w.WriteHeader(http.StatusNoContent) // success
	w.Write(rspData)

	return
}

func waitContainer(w http.ResponseWriter, req *http.Request) (retErr error){
	log.Printf("wait for the plugin command\n")

	if lockPluginCmd() == false {
		w.WriteHeader(http.StatusInternalServerError)
		responseMsg(w, "another request is running")
		return		
	}
	waitPluginCmd := pluginCmd
	unlockPluginCmd()
	
	if waitPluginCmd == nil || waitPluginCmd.Process == nil {
		w.WriteHeader(http.StatusOK) // success
		return
	}

	atomic.StoreInt32(&waitPluginCmdF, 1) // set
	waitPluginCmd.Wait()
	atomic.StoreInt32(&waitPluginCmdF, 0) // done
	w.WriteHeader(http.StatusOK) // success

	if lockPluginCmd() == true {
		defer unlockPluginCmd()
		pluginCmd = nil
	}
	
	return
}

func initPluginExecutor(podName string) {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)

	go func() {
		caughtSig := <- sigCh
		log.Printf("got signal: %v\n", caughtSig)
		
		if lockPluginCmd() == true {
			defer unlockPluginCmd()
		}

		if pluginCmd == nil || pluginCmd.Process == nil {
			os.Exit(1)
		}
			
		pluginCmd.Process.Kill()
		err := pluginCmd.Wait()
		if err != nil {
			for atomic.LoadInt32(&waitPluginCmdF) == 1 {
				time.Sleep(time.Second)
			}
		}

		os.Exit(1)
	}()

	expectCont = "dev-" /*networkID*/ + podName + "-hlRsyslog-5.0" /*Chaincode Name*/
	digest := sha256.Sum256([]byte(expectCont))
	digestStr := hex.EncodeToString(digest[:])
	expectImg = strings.ToLower(expectCont) + "-" + digestStr

	http.HandleFunc("/", nopHandler)
	http.HandleFunc("/version", dockerVersion)
	http.HandleFunc("/containers/", containerOp)
	http.HandleFunc("/containers/create", createContainer)

	go func() {
		err := http.ListenAndServe(":2376", nil)
		if err != nil {
			log.Printf("failed in the plugin executor: %s\n", err)
		}

		syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	}()

	return
}
