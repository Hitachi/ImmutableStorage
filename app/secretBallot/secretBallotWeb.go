/*
Copyright Hitachi, Ltd. 2021 All Rights Reserved.

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
	"strings"
	"strconv"
	"errors"
	"time"
	"syscall/js"
	"encoding/json"

	"websto"
	"immclient"
	"ballotcli"
	"jpkicli"
)

func getImmsrvURL() string {
	loc := js.Global().Get("location")
	return loc.Get("protocol").String() + "//" + loc.Get("host").String()+"/immsrv"
}

const (
	webAppNfcObj = "webAppNfc"
)

func getWebAppNfc() (webAppNfc js.Value, retErr string) {
	gl := js.Global()
	webAppNfc = gl.Get(webAppNfcObj)
	if webAppNfc.Type() != js.TypeObject {
		retErr = "The NFC function is not found"
		return
	}

	isJPKIF := webAppNfc.Call("isJPKI")
	if isJPKIF.Bool() == false {
		retErr = "This card is not JPKI card"
		return
	}

	return // success
}

func isAvailableJPKI() bool {
	_, err := getWebAppNfc()
	return (err == "")
}

type signCertImp struct{}
func (si *signCertImp) SignData(pin, digest string) (signatureJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)
	return webAppNfc.Call("signData", pin, digest).String()
}
func (si *signCertImp) GetCert(pin string) (certJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)
	return webAppNfc.Call("readSignCert", pin).String()
}

type authCertImp struct{}
func (si *authCertImp) SignData(pin, digest string) (signatureJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)	
	return webAppNfc.Call("signDataUsingAuthKey", pin, digest).String()
}
func (si *authCertImp) GetCert(pin string) (certJson string) {
	webAppNfc := js.Global().Get(webAppNfcObj)	
	return webAppNfc.Call("readAuthCert").String()
}

func main() {
	ch := make(chan struct{}, 0)
	registerCallback()
	makeContent()
	<- ch
}

func registerCallback() {
	gl := js.Global()
	gl.Set("selectedVoterAuthMethod", js.FuncOf(selectedVoterAuthMethod))
	gl.Set("registerVoter", js.FuncOf(registerVoter))
	gl.Set("recordSealPubKey", js.FuncOf(recordSealPubKey))
	gl.Set("setPapers", js.FuncOf(setPapers))
	gl.Set("addCandidate", js.FuncOf(addCandidate))
	gl.Set("removeCandidate", js.FuncOf(removeCandidate))
	gl.Set("addPaperTemplate", js.FuncOf(addPaperTemplate))
	gl.Set("removePaper", js.FuncOf(removePaper))
	gl.Set("storePaperTemplates", js.FuncOf(storePaperTemplates))
	gl.Set("cancelStoringTemplates", js.FuncOf(cancelStoringTemplates))
	gl.Set("setPollTimes", js.FuncOf(setPollTimes))
	gl.Set("setPollTimesBtns", js.FuncOf(setPollTimesBtns))
	gl.Set("openBallotBox", js.FuncOf(openBallotBox))
	gl.Set("countVotes", js.FuncOf(countVotes))
	gl.Set("selectVoter", js.FuncOf(selectVoter))
	gl.Set("selectedVoterType", js.FuncOf(selectedVoterType))
	gl.Set("vote", js.FuncOf(vote))
	gl.Set("reqBoxOK", js.FuncOf(reqBoxOK))
	gl.Set("reqBoxCancel", js.FuncOf(reqBoxCancel))
}

func makeContent() {
	go func() {
		id, err := websto.GetCurrentID()
		if err != nil {
			makeVoterContent(nil)
			return
		}
		
		role := id.GetRole()
		switch role {
		case ballotcli.ROLE_AdminOfficial:
			makeAdminElectionOfficialContent()
		case ballotcli.ROLE_ElectionOfficial:
			makeElectionsOfficialContent()
		case ballotcli.ROLE_AdminVoterReg:
			makeVoterRegContent()
		case ballotcli.ROLE_VoterReg:
			// nothing
		case ballotcli.ROLE_Voter:
			makeVoterContent(id)
		default:
			makeVoterContent(nil)
		}
	}()
}

func makeVoterContent(id *immclient.UserID) {
	if id != nil {
		err := makeResultVoteContent(id)
		if err != nil {
			makeVoteContent(id)
		}
		return
	}
	
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="cert-area">
      <div class="row">
        <div class="cert-item"><label for="type">Authentication method</label></div>
        <div class="cert-input">
          <select id="voterAuthMethod" onchange="selectedVoterAuthMethod()">
            <option value="pass">Username and password</option>`
	if isAvailableJPKI() {
		html +=`
            <option value="JPKI">JPKI card</option>`
	}
	html +=`
          </select>
        </div>
      </div>
      <div id="userAttrArea"></div>
      <div class="row">
        <div class="immDSBtn">
          <button onclick="registerVoter()" id="registerVoterBtn">Register</button>
        </div>
      </div>
      <div class="row">
        <p id="registerVoterResult"></p>
      </div>
      </div>`

	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)

	authMethodSel := doc.Call("getElementById", "voterAuthMethod")
	authMethodSel.Call("onchange")
}

func selectedVoterAuthMethod(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	authMethodSel := doc.Call("getElementById", "voterAuthMethod")
	authMethod := authMethodSel.Get("value").String()

	html := ""
	switch authMethod {
	case "pass":
		html += `
        <div class="row">
          <div class="cert-item"><label for="regVoterName" id="regVoterNameLabel">Name</label></div>
          <div class="cert-input"><input type="text" id="regVoterName"></div>
        </div>
        <div class="row">
          <div class="cert-item"><label for="regVoterPass" id="regVoterPassLabel">Password</label></div>
          <div class="cert-input"><input type="password" id="regVoterPass"></div>
        </div>`
	case "JPKI":
	}

	userAttrArea := doc.Call("getElementById", "userAttrArea")
	userAttrArea.Set("innerHTML", html)
	return nil
}

func registerVoter(this js.Value, in []js.Value) interface{} {
	url := getImmsrvURL()
	doc := js.Global().Get("document")
	authMethodSel := doc.Call("getElementById", "voterAuthMethod")
	authMethod := authMethodSel.Get("value").String()
	result := doc.Call("getElementById", "registerVoterResult")

	go func() {
		switch authMethod {
		case "pass":
			voterNameObj := doc.Call("getElementById", "regVoterName")
			voterName := voterNameObj.Get("value").String()

			if voterName == "" {
				return
			}

			voterName = strings.TrimSuffix(voterName, ballotcli.VoterGrp)
			voterName += ballotcli.VoterGrp
			voterNameObj.Set("value", voterName)
			

			pass := doc.Call("getElementById", "regVoterPass").Get("value").String()
			id, err := immclient.EnrollUser(voterName, immclient.OneYear, pass, url)
			if err != nil {
				result.Set("innerHTML", err.Error())
				return
			}

			// save a user key-pair into the local storage
			websto.StoreKeyPair(voterName, id)
			websto.SetCurrentUsername(id.Name)

			makeVoteContent(id)
		case "JPKI":
			jpkiMakeExportAuthCertBoxContent()
		default:
			result.Set("innerHTML", "Unknown authentication method")
		}
	}()
	return nil
}

func jpkiMakeExportAuthCertBoxContent() {
	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	html += `  <label>You will send your certificate for authentication. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	html += `  <input type="number" id="authPIN">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOK(event, 'exportAuthCert')" id="reqBoxOkBtn">OK</button>`
	html += `    <button onclick="reqBoxCancel(event, 'exportAuthCert')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="exportAuthCertResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")	
}

var gRegUser *jpkicli.RegisterJPKIUserRequest

func exportAuthCertOK(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")

	pin := doc.Call("getElementById", "authPIN").Get("value").String()
	if pin == "" {
		return // ignore
	}

	result := doc.Call("getElementById", "exportAuthCertResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}

	rsp, err := jpkicli.GenerateSignature(&authCertImp{}, pin)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	gRegUser = &jpkicli.RegisterJPKIUserRequest{}
	gRegUser.AuthDigest = rsp.Digest
	gRegUser.AuthSignature = rsp.Signature
	gRegUser.AuthCert = rsp.CertAsn1
	
	closeReqBox(nil)
	makeExportSignCertBoxContent()
	return
}

func makeExportSignCertBoxContent() {
	gl := js.Global()
	doc := gl.Get("document")

	html := `<div class="passReqArea">`
	html += `  <label>You will send your certificate for signature. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	html += `  <input type="text" id="signPin">`
	html += `  <div class="immDSBtn">`
	html += `    <button onclick="reqBoxOK(event, 'exportSignCert')" id="reqBoxOkBtn">OK</button>`
	html += `    <button onclick="reqBoxCancel(event, 'exportSignCert')" id="reqBoxCancelBtn">Cancel</button>`
	html += `    <p id="exportSignCertResult"></p>`
	html += `  </div>`
	html += `</div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")			
}

func exportSignCertOK(in []js.Value) {
	url := getImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")

	pin := doc.Call("getElementById", "signPin").Get("value").String()
	if pin == "" {
		return // ignore
	}

	result := doc.Call("getElementById", "exportSignCertResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}

	if gRegUser == nil {
		visibleErrMsg("unexpected state")
		return
	}

	rsp, err := jpkicli.GenerateSignature(&signCertImp{}, pin)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	gRegUser.SignDigest = rsp.Digest
	gRegUser.SignSignature = rsp.Signature
	gRegUser.SignCert = rsp.CertAsn1
	gRegUser.GroupName = ballotcli.VoterGrpForJPKI

	voterName, err := jpkicli.RegisterJPKIUser(url, gRegUser)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	enrollReq := &jpkicli.EnrollJPKIUserRequest{
		Digest: rsp.Digest,
		Signature: rsp.Signature,
		SignPub: rsp.PubAsn1,
	}
	privPem, certPem, err := jpkicli.EnrollJPKIUser(url, voterName, enrollReq)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	id := &immclient.UserID{Name: voterName, Priv: privPem, Cert: certPem, }
	websto.StoreKeyPair(voterName, id)
	websto.SetCurrentUsername(id.Name)
	
	closeReqBox(nil)
	makeVoteContent(id)
	return // success
}

func errorMsgBoxContent(msg string) {
	gl := js.Global()
	doc := gl.Get("document")
	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBox := doc.Call("getElementById", "reqBox")

	html := `
      <div class="passReqArea"> 
        <label>` + msg + `</label>
		<div class="immDSBtn">
          <button onclick="reqBoxOK(event, 'errorMsgBox')" id="reqBoxOkBtn">OK</button>
        </div>
      </div>`
	reqBoxContent.Set("innerHTML", html)
	reqBox.Get("style").Set("display", "block")
}

var cachePapers *[]ballotcli.Paper = nil

func makeVoteContent(id *immclient.UserID) {
	url := getImmsrvURL()
	gl := js.Global()
	doc := gl.Get("document")
	ballotContent := doc.Call("getElementById", "ballotContent")

	state, err := ballotcli.GetMyVoterState(id, url)
	if err != nil {
		errorMsgBoxContent(err.Error())
		return
	}

	if state != "registered" {
		if state != "voted" {
			errorMsgBoxContent("invalid state: " + state)
			return
		}

		html := "<label>You have already voted.</lable>"
		ballotContent.Set("innerHTML", html)
		return
	}
	
	papers, err := ballotcli.GetPaper(id, url)
	if err != nil {
		errorMsgBoxContent(err.Error())
		return
	}
	cachePapers = papers

	html := `
      <div class="cert-area">
        <div class="row">
          <div class="cert-itme"><label>Papers</label>
        </div>`
	for i, paper := range *papers {
		paperNo := "paper" + strconv.Itoa(i)
		html += `
        <div class="row">
          <div class="cert-itme"><label>`+ strconv.Itoa(i) + ". " + paper.Description + `</label>
		</div>`

		switch paper.Method {
		case ballotcli.PAPER_METHOD_RADIO:
			for j, candidate := range paper.Candidates {
				candidateNo := paperNo + "." + strconv.Itoa(j)
				html += `<div class="row">`
				html += `<label class="radioArea">`
				html += `  <input type="radio" name="` + paperNo + `" value="` + candidateNo + `">`
				html += `  <span class="radioBox"></span>`
				html += candidate.Name
				html += "</label>"
				html += "</div>"
			}
		case ballotcli.PAPER_METHOD_DISAPPROVAL:
			for j, candidate := range paper.Candidates {
				candidateNo := paperNo + "." + strconv.Itoa(j)
				html += `<div class="row">`
				html += `  <div class="cert-item"><label>` + candidate.Name + "</label></div>"
				html += `  <div class="cert-input"><label class="checkbox">disapproval<input type="checkbox" id="` + candidateNo + `"><span class="checkmark"></span></label></div>`
				html += `</div>`
			}             
		case ballotcli.PAPER_METHOD_RANK:
			for k := 1; k <= len(paper.Candidates); k++ {
				rankNo := paperNo  + ".rank" + strconv.Itoa(k)
				html += `<div class="row">`
				html += "Select crandidte No." + strconv.Itoa(k)
				html += `</div>`
				
				html += `<div class="row">`
				for j, candidate := range paper.Candidates {
					candidateNo := paperNo + "." + strconv.Itoa(j)
					html += `<label class="radioArea">`
					html += `  <input type="radio" name="` + rankNo + `" value="` + candidateNo + `">`
					html += `  <span class="radioBox"></span>`
					html += candidate.Name
					html += "</label>"
				}
				html += `</div>`
			}
		default:
			errorMsgBoxContent("unexpected paper type: " + paper.Method)
			return
		}
		
	}
	
	html += `
        <div class="row">
          <div class="immDSBtn">
            <button onClick="vote()" id="voteBtn">Vote</button>
          </div>
        </div>
      </div>`


	ballotContent.Set("innerHTML", html)
}

func vote(this js.Value, in []js.Value) interface{} {
	if cachePapers == nil {
		errorMsgBoxContent("Failed to get paper templates")
		return nil
	}

	gl := js.Global()
	doc := gl.Get("document")
	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBox := doc.Call("getElementById", "reqBox")
	
	html := `
      <div class="cert-area">
        <div class="row">
          <div class="cert-itme"><label>You will vote the following papers. Are you sure?</label>
        </div>`

	for i, paper := range *cachePapers {
		paperNo := "paper" + strconv.Itoa(i)
		html += `
        <div class="row">
          <div class="cert-itme"><lable>`+ strconv.Itoa(i) + ". " + paper.Description + `</title>
		</div>`

		switch paper.Method {
		case ballotcli.PAPER_METHOD_RADIO:
			selectedCandidate := doc.Call("querySelector", "input[name=\""+paperNo+"\"]:checked").Get("value").String()
			selectedNo, err := strconv.Atoi(strings.TrimPrefix(selectedCandidate, paperNo+"."))
			if err != nil {
				errorMsgBoxContent("unexpected string")
				return nil
			}
			
			candidate := paper.Candidates[selectedNo]
			html += `<div class="row">`
			html += candidate.Name
			html += "</div>"

			// clear candidates and select a candidate
			for j := 0; j < len(paper.Candidates); j++ {
				(*cachePapers)[i].Candidates[j].VoterInput = ""
			}
			(*cachePapers)[i].Candidates[selectedNo].VoterInput = "selected"
		case ballotcli.PAPER_METHOD_DISAPPROVAL:
			for j, candidate := range paper.Candidates {
				candidateNo := paperNo + "." + strconv.Itoa(j)
				state := "approval"
				if doc.Call("getElementById", candidateNo).Get("checked").Bool() {
					state = "disapproval"
				}
				
				html += `<div class="row">`
				html += `  <div class="cert-item"><label>` + candidate.Name + "</label></div>"
				html += `  <div class="cert-input"><lable>` + state + "</label></div>"
				html += `</div>`

				(*cachePapers)[i].Candidates[j].VoterInput = state
			}
		case ballotcli.PAPER_METHOD_RANK:
			noOfCandidates := len(paper.Candidates)
			scores := make([]int, noOfCandidates)
			
			for k := 1; k <= noOfCandidates; k++ {
				rankNo := paperNo  + ".rank" + strconv.Itoa(k)
				selectedCandidate := doc.Call("querySelector", "input[name=\""+rankNo+"\"]:checked").Get("value").String()
				selectedNo, err := strconv.Atoi(strings.TrimPrefix(selectedCandidate, paperNo+"."))
				if err != nil {
					errorMsgBoxContent("unexpected string")
					return nil
				}
				candidate := paper.Candidates[selectedNo]

				html += `<div class="row">`
				html += `  <div class="cert-item"><label>Selected rank No.` + strconv.Itoa(k) + ": </label></div>"
				html += `  <div class="cert-input"><lable>` +  candidate.Name + "</label></div>"
				html += `</div>`

				scores[selectedNo] += (noOfCandidates - k - 1)
			}

			for j := 0; j < noOfCandidates; j++ {
				(*cachePapers)[i].Candidates[j].VoterInput = strconv.Itoa(scores[j])
			}
		}
	}
	
	html += `
        <div class="row">
          <div class="immDSBtn">
            <button onclick="reqBoxOK(event, 'vote')" id="reqBoxOkBtn">OK</button>
            <button onclick="reqBoxCancel(event, 'vote')" id="reqBoxCancelBtn">Cancel</button>
          </div> 
        </div> 
      <div>`

	reqBoxContent.Set("innerHTML", html)
	reqBox.Get("style").Set("display", "block")
	return nil
}

func voteOK(in []js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		closeReqBox(nil)
		errorMsgBoxContent("failed to get your ID: " + err.Error())
		return
	}
	url := getImmsrvURL()

	err = ballotcli.Vote(id, url, cachePapers)
	if err != nil {
		errorMsgBoxContent(err.Error())
		return
	}
	
	closeReqBox(nil)
	return // success
}

func makeAdminElectionOfficialContent() {
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="cert-area">
        <div class="immDSBtn">
        <div class="row">
          <button onclick="recordSealPubKey()" id="recordSealPubKeyBtn" name="` +ballotcli.ROLE_AdminOfficial+ `">Record your public key to seal the ballot box</button>
        </div>
        <div class="row">
          <button onclick="setPapers()" id="setPapersBtn">Set paper templates</button>
        </div>
        <div class="row">
          <button onclick="setPollTimes()" id="setPollTimesBtn">Set poll times</button>
        </div>
        <div class="row">
          <button onclick="openBallotBox()" id="openBallotBoxBtn">Open the ballot box</button>
        </div>
        </div>
      </div>`
	
	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)
}

var cachePaperTemp *ballotcli.Paper
var cachePaperTemps []ballotcli.Paper

func setPapers(this js.Value, in []js.Value) interface{} {
	cachePaperTemp = &ballotcli.Paper{}
	
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="cert-area">
        <div class="row">
          <label>Paper template</label>
        </div>
        <div class="row">
          <div class="cert-item"><label for="paperDescription">This paper description:</label></div>
          <div class="cert-input"><input type="text" id="paperDescription"></input></div>
        </div>
        <div class="row">
          <div class="cert-item"><label for="votingMethod">Voting method</label></div>
          <div class="cert-input">
            <select id="votingMethod" onchange="selectedVotingMethod()">
              <option value="`+ballotcli.PAPER_METHOD_RADIO+`">Selecting one candidate</option>
              <option value="`+ballotcli.PAPER_METHOD_DISAPPROVAL+`">Marking disapproval candidates</option>
              <option value="`+ballotcli.PAPER_METHOD_RANK+`">Ranking candidates in numerical order</option>
            </select>
          </div>
        </div>

        <div id="listCandidatesArea"></div>
        <div class="row">
          <div class="cert-item"><label for="candidateName">Candidate name: </label></div>
          <div class="cert-input"><input type="text" id="candidateName"></div>
        </div>
        <div class="row">
          <div class="immDSBtn"><button onclick="addCandidate()" id="addCandidateBtn">Add a candidate</button></div>
        </div>
        <br>
        <div class="row">
          <div class="immDSBtn"><button onclick="addPaperTemplate()" id="addPaperBtn">Add a paper template</button></div>
        </div>
        <div id="listPaperTemplatesArea"></div>
      </div>`

	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)
	return nil
}

func addCandidate(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

	name := doc.Call("getElementById", "candidateName").Get("value").String()
	cachePaperTemp.Candidates = append(cachePaperTemp.Candidates, ballotcli.Candidate{Name: name})
	updateListCandidatesArea()
	return nil
}

func updateListCandidatesArea() {
	gl := js.Global()
	doc := gl.Get("document")
	
	listCandidateArea := doc.Call("getElementById", "listCandidatesArea")

	html := ""
	for i, candidate := range cachePaperTemp.Candidates {
		html += `
          <div class="row">
            <div class="cert-item"><label>` + candidate.Name +`</label></div>
            <div class="cert-input">
              <div class="immDSBtn">
                <button onclick="removeCandidate(event)" name="candidateNo`+strconv.Itoa(i)+`">Remove</button>
              </div>
            </div>
		  </div>`
	}
	
	listCandidateArea.Set("innerHTML", html)
}

func removeCandidate(this js.Value, in []js.Value) interface{} {
	removeBtn := in[0].Get("target")
	candidateNoStr := removeBtn.Get("name").String()
	candidateNo, _ := strconv.Atoi(strings.TrimPrefix(candidateNoStr, "candidateNo"))

	tmpList := cachePaperTemp.Candidates[:candidateNo]
	cachePaperTemp.Candidates = append(tmpList, cachePaperTemp.Candidates[candidateNo+1:]...)

	updateListCandidatesArea()
	return nil
}

func addPaperTemplate(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

	cachePaperTemp.Description = doc.Call("getElementById", "paperDescription").Get("value").String()
	cachePaperTemp.Method = doc.Call("getElementById", "votingMethod").Get("value").String()
	if len(cachePaperTemp.Candidates) <= 0 {
		return nil // no candidate
	}

	cachePaperTemps = append(cachePaperTemps, *cachePaperTemp)
	updateListPaperTemps()

	cachePaperTemp = &ballotcli.Paper{}
	updateListCandidatesArea()
	return nil
}

var methodStr = map[string] string{
	ballotcli.PAPER_METHOD_RADIO: "Selecting one candidate",
	ballotcli.PAPER_METHOD_DISAPPROVAL: "Marking disapproval candidates",
	ballotcli.PAPER_METHOD_RANK: "Ranking candidates in numerical order",
}

func updateListPaperTemps() {
	gl := js.Global()
	doc := gl.Get("document")

	listPaperTempsArea := doc.Call("getElementById", "listPaperTemplatesArea")

	html := ""
	for i, paper := range cachePaperTemps {
		html += `
          <div class="row">
            <div class="cert-item"><label>No.`+strconv.Itoa(i+1)+`</label></div>
            <div class="cert-input">
              <div class="immDSBtn">
                <button onclick="removePaper(event)" name="paperNo`+strconv.Itoa(i)+`">Remove</button>
              </div>
            </div>
          </div>
          <div class="row">
            <div class="cert-item"><label>Desciption:</label></div>
            <div class="cert-input"><label>`+paper.Description+`</label></div>
          </div>
          <div class="row">
            <div class="cert-item"><label>Method:</label></div>
            <div class="cert-input"><label>`+methodStr[paper.Method]+`</label></div>
          </div>`
		
		for _, candidate := range paper.Candidates {
			html += `
          <div class="row">
            <div class="cert-item"><label>Candidate: </label></div>
            <div class="cert-input"><label>`+ candidate.Name+`</label></div>
          </div>`
		}
	}

	if len(cachePaperTemps) > 0 {
		html += `
          <div class="row">
            <div class="cert-item">
            <div class="immDSBtn">
              <button onclick="storePaperTemplates()">Store paper templates</button>
            </div>
            </div>

            <div class="cert-input">
            <div class="immDSBtn">
              <button onclick="cancelStoringTemplates()">Cancel</button>
            </div>
            </div>
          </div>`
	}

	listPaperTempsArea.Set("innerHTML", html)
}

func removePaper(this js.Value, in []js.Value) interface{} {
	removeBtn := in[0].Get("target")
	paperNoStr := removeBtn.Get("name").String()
	paperNo, _ := strconv.Atoi(strings.TrimPrefix(paperNoStr, "paperNo"))

	tmpList := cachePaperTemps[:paperNo]
	cachePaperTemps = append(tmpList, cachePaperTemps[paperNo+1:]...)

	updateListPaperTemps()
	return nil
}

func storePaperTemplates(this js.Value, in []js.Value) interface{} {
	url := getImmsrvURL()
	go func() {
		id, _ := websto.GetCurrentID()
		err := ballotcli.SetPaper(id, url, &cachePaperTemps)
		if err != nil {
			errorMsgBoxContent(err.Error())
			return
		}

		makeAdminElectionOfficialContent() // go to previous content
		errorMsgBoxContent("Success") // visible success message
		return
	}()
	return nil
}

func cancelStoringTemplates(this js.Value, in []js.Value) interface{} {
	makeAdminElectionOfficialContent()
	return nil
}

func openBallotBox(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="passReqArea">
        <label>You will open the ballot box.</label>
        <div class="immDSBtn">
          <button onclick="reqBoxOK(event, 'openBallotBox')" id="reqBoxOkBtn">OK</button>
          <button onclick="reqBoxCancel(event, 'openBallotBox')" id="reqBoxCancelBtn">Cancel</button>
        </div>
      </div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")
	return nil
}

func openBallotBoxOK(in []js.Value) {
	url := getImmsrvURL()
	go func() {
		id, _ := websto.GetCurrentID()
		err := ballotcli.OpenBallotBox(id, url)
		if err != nil {
			closeReqBox(nil)
			errorMsgBoxContent(err.Error())
			return
		}

		closeReqBox(nil)
		errorMsgBoxContent("Success")
		return
	}()
}

func makeElectionsOfficialContent() {
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="immDSBtn">
        <div class="row">
          <button onclick="recordSealPubKey()" id="recordSealPubKeyBtn" name="` +ballotcli.ROLE_ElectionOfficial+ `">Record your public key to seal ballot papers</button>
        </div>
        <div class="row">
          <button onclick="countVotes()" id="countVotesBtn">Count votes</button>
        </div>
      </div>`
	
	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)
}

func recordSealPubKey(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")
	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBox := doc.Call("getElementById", "reqBox")
	
	role := doc.Call("getElementById", "recordSealPubKeyBtn").Get("name").String()

	visibleErrMsg := func(msg string) {
		msgHtml := `
            <div class="passReqArea"> 
			  <label>` + msg + `</label>
			  <div class="immDSBtn">
                 <button onclick="reqBoxCancel(event, 'recordSealPubKey')" id="reqBoxCancelBtn">OK</button>
              </div>
            </div>`
		reqBoxContent.Set("innerHTML", msgHtml)
		reqBox.Get("style").Set("display", "block")
	}
	
	go func() {
		html := `
        <div class="passReqArea">
          <div class="row"><label>You will record your public key to Immutable Storage.</label></div>`
	 
		if role == ballotcli.ROLE_AdminOfficial {
			url := getImmsrvURL()
			id, err := websto.GetCurrentID()
			if err != nil {
				visibleErrMsg(err.Error())
				return
			}
			
			storageGrpList, err := id.ListAvailableStorageGroup(url)
			if err != nil || len(storageGrpList) == 0 {
				visibleErrMsg("Not found avaliable storage group")
				return
			}
		
			html += `
            <div class="row">
              <div class="cert-item"><label for="storageGrp">Storage group</label></div>
              <div class="cert-input">
                <select id="recordStorageGrp">`
			for _, storageGrp := range storageGrpList {
				html += `
                  <option value="`+storageGrp+`">`+storageGrp+`</option>`
			}
			html += `
                </select>
              </div>
            </div>`
		}
	
		html += `
          <div class="row">
          <div class="immDSBtn">
            <button onclick="reqBoxOK(event, 'recordSealPubKey')" id="reqBoxOkBtn" name="` + role + `">OK</button>
            <button onclick="reqBoxCancel(event, 'recordSealPubKey')" id="reqBoxCancelBtn">Cancel</button>
          </div>
          </div>
          <div class="row">
            <p id="recordSealPubKeyResult"></p>
          </div>
        </div>`
	
		reqBoxContent.Set("innerHTML", html)
		reqBox.Get("style").Set("display", "block")
	}()

	return nil
}

func recordSealPubKeyOK(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	
	result := doc.Call("getElementById", "recordSealPubKeyResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}
	
	id, err := websto.GetCurrentID()
	if err != nil {
		visibleErrMsg("Failed to get your ID")
		return
	}

	role := in[0].Get("target").Get("name").String()
	url := getImmsrvURL()
	
	if role == ballotcli.ROLE_AdminOfficial {
		storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
		storageGrp := storageGrpSel.Get("value").String()

		err := ballotcli.CreateBox(id, url, storageGrp)
		if err != nil {
			visibleErrMsg(err.Error())
			return
		}
		closeReqBox(nil)
		return // success
	}
	
	// role == ROLE_ElectionOfficial
	err = ballotcli.SetSealPubKey(id, url)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}

	closeReqBox(nil)
	return // success
}

func setPollTimes(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

	now := time.Now()
	
	html := `
      <div class="cert-area">
        <div class="row">
          <label>You will set poll opening and closing times.</label>
        </div>

        <div class="row">
          <div class="cert-item"><label>Opening time:</label></div>
          <div class="date-input">
            <label>Day</label><input type="text" id="openingTimeYear" value="`+strconv.Itoa(now.Year())+`"></input>
            <label>-</label><input type="text" id="openingTimeMonth" value="`+strconv.Itoa(int(now.Month()))+`"></input>
            <label>-</label><input type="text" id="openingTimeDay" value="`+strconv.Itoa(now.Day())+`"></input>
            <label> Time</label><input type="text" id="openingTimeHour" value="0"></input>
            <label>:</label><input type="text" id="openingTimeMins" value="0"></input>
          </div>
        </div>

        <div class="row">
          <div class="cert-item"><label>Closing time:</label></div>
          <div class="date-input">
             <label>Day</label><input type="text" id="closingTimeYear" value="`+strconv.Itoa(now.Year())+`"></input>
             <label>-</label><input type="text" id="closingTimeMonth" value="`+strconv.Itoa(int(now.Month()))+`"></input>
             <label>-</label><input type="text" id="closingTimeDay" value="`+strconv.Itoa(now.Day())+`"></input>
             <label> Time</label><input type="text" id="closingTimeHour" value="0"></input>
             <label>:</label><input type="text" id="closingTimeMins" value="0"></input>
          </div>
        </div>

        <div class="row">
          <div class="immDSBtn">
            <button onclick="setPollTimesBtns(event)" name="OK">OK</button>
            <button onclick="setPollTimesBtns(event)" name="Cancel">Cancel</button>
          </div>
        </div>
      </div>`

	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)
	return nil
}

func itoa02(i int) (str string) {
	str = ""
	if i < 10 {
		str = "0"
	}
	str += strconv.Itoa(i)
	return
}

func curTimeOffset() string {
	_, offset := time.Now().Zone()
	offsetSign := "+"
	if offset < 0 {
		offset *= -1
		offsetSign = "-"
	}
	offsetHour := offset/60/60
	offsetMins := (offset/60)%60
	return offsetSign+itoa02(offsetHour)+":"+itoa02(offsetMins)
}
	
func convRFC3339Time(namePrefix string, offsetStr string) (t string, retErr error) {
	gl := js.Global()
	doc := gl.Get("document")
	
	validRange := map[string] struct{
		min int
		max int
		tail string
	}{
		"Year": {2021, 2100, "-"},
		"Month": {1, 12, "-"},
		"Day": {1, 31, "T"},
		"Hour": {0, 23, ":"},
		"Mins": {0, 59, ""},
	}
	
	for tType, vRange := range validRange {
		item :=  doc.Call("getElementById", namePrefix+tType).Get("value").String()
		i, err := strconv.Atoi(item)
		if err != nil {
			retErr = errors.New("invalid character")
			return
		}
	
		if i < vRange.min {
			retErr = errors.New("out of range")
			return
		}
	
		if i > vRange.max {
			retErr = errors.New("out of range")			
			return
		}

		t += itoa02(i) + vRange.tail
	}

	t += offsetStr
	return // success
}

func setPollTimesBtns(this js.Value, in []js.Value) interface{} {
	action := in[0].Get("target").Get("name").String()

	if action != "OK" {
		makeAdminElectionOfficialContent()
		return nil
	}

	reqPollTimes := &ballotcli.PollTimes{}
	pollTimes := map[string] *string{
		"openingTime": &reqPollTimes.OpeningTime,
		"closingTime": &reqPollTimes.ClosingTime,
	}
	
	offset := curTimeOffset()
	for tType, setP := range pollTimes {
		var err error
		*setP, err = convRFC3339Time(tType, offset)
		if err != nil {
			errorMsgBoxContent(err.Error())
			return nil
		}
	}

	go func() {
		id, _ := websto.GetCurrentID()
		url := getImmsrvURL()
		err := ballotcli.SetPollTimes(id, url, reqPollTimes)
		if err != nil {
			errorMsgBoxContent(err.Error())
			return
		}

		// success
		errorMsgBoxContent("Success")
		makeAdminElectionOfficialContent()
		return
	}()
	
	return nil
}

func countVotes(this js.Value, in []js.Value) interface{} {
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="passReqArea">
        <label>You will count votes in the ballot box.</label>
        <div class="immDSBtn">
          <button onclick="reqBoxOK(event, 'countVotes')" id="reqBoxOkBtn">OK</button>
          <button onclick="reqBoxCancel(event, 'countVotes')" id="reqBoxCancelBtn">Cancel</button>
          <p id="countVotesResult"></p>
        </div>
      </div>`

	reqBoxContent := doc.Call("getElementById", "reqBoxContent")
	reqBoxContent.Set("innerHTML", html)

	
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "block")
	return nil
}

func countVotesOK(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	
	result := doc.Call("getElementById", "countVotesResult")
	okBtn := doc.Call("getElementById", "reqBoxOkBtn")
	var visibleErrMsg = func(msg string) {
		okBtn.Set("hidden", false)
		result.Set("innerHTML", msg)
	}
	
	id, err := websto.GetCurrentID()
	if err != nil {
		visibleErrMsg("Failed to get your ID")
		return
	}

	url := getImmsrvURL()
	err = ballotcli.CountVotes(id, url)
	if err != nil {
		visibleErrMsg(err.Error())
		return
	}
	
	closeReqBox(nil) // success
	return
}

func reqBoxAction(in []js.Value, funcSuffix string) interface{} {
	if len(in) != 2 {
		return nil
	}
	reqStr := in[1].String() + funcSuffix

	reqFunc, ok := reqBoxFunc[reqStr]
	if !ok {
		return nil
	}

	go reqFunc(in)
	return nil
}

var reqBoxFunc = map[string] func([]js.Value){
	"recordSealPubKeyOK": recordSealPubKeyOK,
	"recordSealPubKeyCancel": closeReqBox,
	"errorMsgBoxOK": closeReqBox,
	"voteOK": voteOK,
	"voteCancel": closeReqBox,
	"openBallotBoxOK": openBallotBoxOK,
	"openBallotBoxCancel": closeReqBox,
	"countVotesOK": countVotesOK,
	"countVotesCancel": closeReqBox,
	"exportAuthCertOK": exportAuthCertOK,
	"exportAuthCertCancel": closeReqBox,
	"exportSignCertOK": exportSignCertOK,
	"exportSignCertCancel": closeReqBox,
}

func closeReqBox(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	reqBox := doc.Call("getElementById", "reqBox")
	reqBox.Get("style").Set("display", "none")	
}

func reqBoxOK(this js.Value, in []js.Value) interface{} {
	return reqBoxAction(in, "OK")
}

func reqBoxCancel(this js.Value, in []js.Value) interface{} {
	return reqBoxAction(in, "Cancel")
}

func makeVoterRegContent() {
	gl := js.Global()
	doc := gl.Get("document")

	html := `
      <div class="cert-area">
        <div class="row">
          <div class="cert-item"><label for="vooterAuthType">Voter type</label></div>
          <div class="cert-input">
            <select id="voterAuthType" onchange="selectedVoterType()">
              <option value="CAVoter">Select votors marked voter on CA DB</option>
              <option value="LDAPVoter">Select voters from the LDAP</option>
              <option value="JPKIVoter">Select voters using JPKI card</option>
            </select>
          </div>
        </div>
        <div id="voterAttrArea" hidden></div>
        <div class="row">
          <div class="immDSBtn">
            <button onclick="selectVoter()" id="selectVoterBtn">Select voters</button>
          </div>
        </div>
        <div class="row">
          <p id="selectVoterResult"></p>
        </div>
      </div>`

	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)
}

func selectedVoterType(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	voterAuthTypeSel := doc.Call("getElementById", "voterAuthType")
	voterAuthType := voterAuthTypeSel.Get("value").String()
	voterAttrArea := doc.Call("getElementById", "voterAttrArea")
	voterAttrAreaHiddenF := false

	html := ""
	switch voterAuthType {
	case "CAVoter":
		voterAttrAreaHiddenF = true
	case "LDAPVoter":
		html += `
          <div class="row">
            <div class="cert-item"><label for="fedGrpName" id="feGrpNameLabel">Federation group name</label></div>
            <div class="cert-input"><input type="text" id="fedGrpName" value="@"></div>
          </div>
          <div class="row" id="bindLDAPServerArea">
            <div class="cert-item"><label for="bindLDAPServer" id="bindLDAPServerLabel">Bind LDAP server</label></div>
            <div class="cert-input"><input type="text" id="bindLDAPServer" value="localhost:389"></div>
          </div>
          <div class="row" id="bindDNArea">
            <div class="cert-item"><label for="bindDN" id="bindDNLabel">Bind DN format</label></div>
            <div class="cert-input"><input type="text" id="bindDN" value='"uid=%s,ou=PEOPLE,o=,c=",sn'></div>
          </div>

          <div class="row" id="queryLDAPServerArea">
            <div class="cert-item"><label for="queryLDAPServer" id="queryLDAPServerLabel">Query LDAP server</label></div>
            <div class="cert-input"><input type="text" id="queryLDAPServer" value="localhost:389"></div>            
          </div>
          <div class="row" id="queryBaseDNArea">
            <div class="cert-item"><label for="queryBaseDN" id="queryBaseDNLabel">Query base DN</label></div>
            <div class="cert-input"><input type="text" id="queryBaseDN" value="ou=PEOPLE,o=,c="></div>            
          </div>
          <div class="row" id="queryLDAPArea">
            <div class="cert-item"><label for="queryLDAP" id="queryLDAPLabel">Query format</label></div>
            <div class="cert-input"><input type="text" id="queryLDAP" value='"(&(objectClass=organizationalPerson)(|(department=de1)(department=de2))(mail=%s))",username'></div>
          </div>`
	case "JPKIVoter":
		html += `
          <div class="row">
            <div class="cert-item"><label for="fedGrpName" id="feGrpNameLabel">Federation group name</label></div>
            <div class="cert-input"><input type="text" id="fedGrpName" value="@"></div>
          </div>
          <div class="row">
            <div class="cert-item"><label for="addressFilter" id="addressFilterLabel">Address filter</label></div>
            <div class="cert-input"><input type="text" id="addressFilter" value="^Earth*"></div>
          </div>
          <div class="row">
            <div class="cert-item"><label for="brithdayFilter" id="birthdayFilter">Birthday filter</label></div>
            <div class="cert-input">
              <input type="text" id="birthdayFilter" value="2001-01-01>=">
              <label>birthday</label>
            </div>
          </div>`
 	}

	voterAttrArea.Set("innerHTML", html)
	voterAttrArea.Set("hidden", voterAttrAreaHiddenF)
	return nil
}

func selectVoter(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	voterAuthType := doc.Call("getElementById", "voterAuthType").Get("value").String()
	selectAuthFunc := map[string] func(id *immclient.UserID, url string) (error){
		"CAVoter": selectVoterCA,
		"LDAPVoter": selectVoterLDAP,
		"JPKIVoter": selectVoterJPKI,
	}

	url := getImmsrvURL()
	go func() {
		result := doc.Call("getElementById", "selectVoterResult")
		id, err := websto.GetCurrentID()
		if err != nil {
			result.Set("innerHTML", "A user is not specified: " + err.Error())
			return
		}
		
		selFunc, ok := selectAuthFunc[voterAuthType]
		if !ok {
			result.Set("innerHTML", "unexpected authentication type: " + voterAuthType)
			return
		}


		err = selFunc(id, url)
		if err != nil {
			result.Set("innerHTML", err.Error())
			return
		}
		result.Set("innerHTML", "Success")
	}()

	return nil
}

func selectVoterCA(id *immclient.UserID, url string) error {
	req := &ballotcli.SelectVoterRequest{
		AuthType: "CA",
	}
	return ballotcli.SelectVoter(id, url, req)
}

func selectVoterLDAP(id *immclient.UserID, url string) error {
	doc := js.Global().Get("document")
	
	grpName := doc.Call("getElementById", "fedGrpName").Get("value").String()
	grpName = strings.TrimPrefix(grpName, "@")
	grpName = strings.ReplaceAll(grpName, "@", "")
	grpName = "@" + grpName
	doc.Call("getElementById", "fedGrpName").Set("value", grpName)
	
	param := &ballotcli.VoterAuthParamLDAP{
		GroupName: grpName,
		BindServer: doc.Call("getElementById", "bindLDAPServer").Get("value").String(),
		BindDN: doc.Call("getElementById", "bindDN").Get("value").String(),
		QueryServer: doc.Call("getElementById", "queryLDAPServer").Get("value").String(),
		BaseDN: doc.Call("getElementById", "queryBaseDN").Get("value").String(),
		Query: doc.Call("getElementById", "queryLDAP").Get("value").String(),
	}

	paramJson, _ := json.Marshal(param)
	req := &ballotcli.SelectVoterRequest{
		AuthType: "LDAP",
		AuthParam: paramJson,
	}
	return ballotcli.SelectVoter(id, url, req)
}

func selectVoterJPKI(id *immclient.UserID, url string) error {
	doc := js.Global().Get("document")

	grpName := doc.Call("getElementById", "fedGrpName").Get("value").String()
	grpName = strings.TrimPrefix(grpName, "@")
	grpName = strings.ReplaceAll(grpName, "@", "")
	grpName = "@" + grpName
	doc.Call("getElementById", "fedGrpName").Set("value", grpName)

	validCmpFlags := []string{"<",">","<=",">="}
	birthdayFilter := doc.Call("getElementById", "birthdayFilter").Get("value").String()
	validF := false
	tmpDay := ""
	var vFlag string
	for _, vFlag = range validCmpFlags {
		tmpDay = strings.TrimSuffix(birthdayFilter, vFlag)
		validF = (tmpDay != birthdayFilter)
		if validF {
			break // valid
		}
	}
	if !validF {
		return errors.New("invalid compare flag")
	}

	birthdayFilter = tmpDay + "T00:00:00" + curTimeOffset()  + vFlag
	
	param := &ballotcli.VoterAuthParamJPKI{
		GroupName: grpName,
		AddressFilter: doc.Call("getElementById", "addressFilter").Get("value").String(),
		BirthdayFilter: birthdayFilter,
	}

	paramJson, _ := json.Marshal(param)
	req := &ballotcli.SelectVoterRequest{
		AuthType: "JPKI",
		AuthParam: paramJson,
	}
	return ballotcli.SelectVoter(id, url, req)
}

func makeResultVoteContent(id *immclient.UserID) error {
	url := getImmsrvURL()
	papers, err := ballotcli.GetResultVote(id, url)
	if err != nil {
		return err
	}

	html := `
      <div class="cert-area">
        <div class="row">
          <label>The results of vote</label>
        </div>`
	for _, paper := range *papers {
		html += `
        <div class="row">
          <div class="cert-item"><label>Desciption:</label></div>
          <div class="cert-input"><label>`+paper.Description+`</label></div>
        </div>
		<div class="row">
          <div class="cert-item"><label>Method:</label></div>
          <div class="cert-input"><label>`+methodStr[paper.Method]+`</label></div>
        </div>`

		html += `
        <table>
          <tr>
		    <td>#</td><td>Candidate name</td><td>Count</td>
		  </tr>`
		
		for j, candidate := range paper.Candidates {
			html += `
              <tr>
                <td>` + strconv.Itoa(j+1) + `</td>
                <td>` + candidate.Name + `</td>
                <td>` + candidate.VoterInput + `</td>
              </tr>`
		}
		html += "</table>"
	}

	doc := js.Global().Get("document")
	ballotContent := doc.Call("getElementById", "ballotContent")
	ballotContent.Set("innerHTML", html)
	return nil // success
}
