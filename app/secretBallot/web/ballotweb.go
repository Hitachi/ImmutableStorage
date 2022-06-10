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

package ballotweb

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
	"webjpki"
	wu "webutil"
	"webcli"
)

type Labels struct{
	AppTitle string
	SetPapersTab string
	OfficialAdmin string
	Official string
	OfficialAdminRole string
	OfficialRole string
	Role string
	SelectBox string
	CreateBoxBtn string
	SealBox string
	AddPaperBtn string
	OpenBoxBtn string
	OpenBox string
	OpenBoxProgress string
	RecordPubKey string
	CountVotes string
	Result string
}
var methodStr = map[string] string{
	ballotcli.PAPER_METHOD_RADIO: "Selecting one candidate",
	ballotcli.PAPER_METHOD_APPROVAL: "Marking approval candidates",
	ballotcli.PAPER_METHOD_DISAPPROVAL: "Marking disapproval candidates",
	ballotcli.PAPER_METHOD_RANK: "Ranking candidates in numerical order",
	ballotcli.PAPER_METHOD_OPINION: "Writing an opinion", // for a suvery question
}

var SurveyModeF bool

var lb *Labels
func RegisterCallback(labels *Labels) {
	lb = labels
	gl := js.Global()
	gl.Set("register", js.FuncOf(register))
	gl.Set("selectedVotingMethod", js.FuncOf(selectedVotingMethod))
	gl.Set("selectedVoterAuthMethod", js.FuncOf(selectedVoterAuthMethod))
	gl.Set("registerVoter", js.FuncOf(registerVoter))
	gl.Set("createBox", js.FuncOf(createBox))
	gl.Set("recordSealPubKey", js.FuncOf(recordSealPubKey))
	gl.Set("addCandidate", js.FuncOf(addCandidate))
	gl.Set("removeCandidate", js.FuncOf(removeCandidate))
	gl.Set("addPaperTemplate", js.FuncOf(addPaperTemplate))
	gl.Set("removePaper", js.FuncOf(removePaper))
	gl.Set("storePaperTemplates", js.FuncOf(storePaperTemplates))
	gl.Set("setPollTimesBtns", js.FuncOf(setPollTimesBtns))
	gl.Set("openBallotBox", js.FuncOf(openBallotBox))
	gl.Set("countVotes", js.FuncOf(countVotes))
	gl.Set("selectVoter", js.FuncOf(selectVoter))
	gl.Set("selectedVoterType", js.FuncOf(selectedVoterType))
	gl.Set("vote", js.FuncOf(vote))

	wu.InitTab("openTab")
	wu.RegisterTab("appSecretBallot", updateAppSecretBallotContent)
	
	wu.RegisterTab("register", updateRegisterContent)
	wu.RegisterTab("registration", updateEnrollContent)

	
	wu.RegisterTab("createBallotBox", updateCreateBallotBoxContent)
	wu.RegisterTab("setPapers", updateSetPapersContent)
	wu.RegisterTab("setPollTimes", updateSetPollTimesContent)
	wu.RegisterTab("openBallotBox", updateOpenBallotBoxContent)

	wu.RegisterTab("recordSealPubKey", updateRecordSealPubKeyContent)
	wu.RegisterTab("countVotes", updateCountVotesContent)

	wu.RegisterTab("selectVoterType", updateSelectVoterTypeContent)

	wu.RegisterTab("vote", updateVoteContent)
	
	
	wu.InitReqBox("reqBoxOK", "reqBoxCancel", "defaultAction")
	wu.AppendReqBox("createBox", createBoxOK, nil)
	wu.AppendReqBox("recordSealPubKey", recordSealPubKeyOK, nil)
	wu.AppendReqBox("vote", voteOK, nil)
	wu.AppendReqBox("openBallotBox", openBallotBoxOK, nil)
	wu.AppendReqBox("countVotes", countVotesOK, nil)
	
	wu.AppendReqBox("exportAuthCert", exportAuthCertOK, nil)
	wu.AppendReqBox("exportSignCert", exportSignCertOK, nil)
}

func MakeContent() {
	doc := js.Global().Get("document")
	ballotContent := doc.Call("getElementById", "ballotContent")

	defaultTab := wu.Tabs["appSecretBallot"]
	
	tabHTML := &wu.TabHTML{}
	tabHTML.AppendTab(defaultTab.MakeHTML(lb.AppTitle, "1"))
	html := tabHTML.MakeHTML()
	ballotContent.Set("innerHTML", html)
	
	defaultTab.GetButton().Call("click")
}

func refreshVoterContent() {
	wu.Tabs["appSecretBallot"].GetButton().Call("click")
}

func updateAppSecretBallotContent(tabC *js.Value) {
	username := "Please register you"
	tabHTML := &wu.TabHTML{}	
	var defaultTab *wu.TabBtn
	
	defer func() {
		html := "<h3>" + username + "</h3>"
		html += `<div class="space"></div>`
		html += tabHTML.MakeHTML()
		tabC.Set("innerHTML", html)

		if defaultTab != nil {
			defaultTab.GetButton().Call("click")
		}
	}()

	id, err := websto.GetCurrentID()
	if err != nil {
		tabHTML.AppendTab(wu.Tabs["registration"].MakeHTML("Registration", "2"))
		return
	}
	username = id.Name
	
	role := id.GetRole()
	switch role {
	case ballotcli.ROLE_AdminOfficial:
		tabHTML.AppendTab(wu.Tabs["register"].MakeHTML("Role", "2"))		
		tabHTML.AppendTab(wu.Tabs["createBallotBox"].MakeHTML("Creating a Box", "2"))
		tabHTML.AppendTab(wu.Tabs["setPapers"].MakeHTML(lb.SetPapersTab, "2"))
		tabHTML.AppendTab(wu.Tabs["setPollTimes"].MakeHTML("Poll Times", "2"))
		tabHTML.AppendTab(wu.Tabs["openBallotBox"].MakeHTML("Opening the Box", "2"))
		username += ": " + lb.OfficialAdmin
		return
	case ballotcli.ROLE_ElectionOfficial:
		tabHTML.AppendTab(wu.Tabs["recordSealPubKey"].MakeHTML("Seal Public Key", "2"))
		tabHTML.AppendTab(wu.Tabs["countVotes"].MakeHTML("Counting votes", "2"))
		username += ": " + lb.Official
		return
	case ballotcli.ROLE_AdminVoterReg:
		tabHTML.AppendTab(wu.Tabs["selectVoterType"].MakeHTML("Selecting Voter Type", "2"))
		tabHTML.AppendTab(wu.Tabs["register"].MakeHTML("Role", "2"))		
		username += ": voter registration administrator"
		return
	case ballotcli.ROLE_VoterReg:
		username += ": voter registration"
		return
	case ballotcli.ROLE_Voter:
		voteTab := wu.Tabs["vote"]
		tabHTML.AppendTab(voteTab.MakeHTML("Vote", "2"))
		username += ": voter"
		defaultTab = voteTab
		return
	default:
		roles := id.GetRegRoles(wu.GetImmsrvURL())
		if len(roles) > 0 && roles[0] == "*" {
			tabHTML.AppendTab(wu.Tabs["register"].MakeHTML("Role", "2"))
		}
		tabHTML.AppendTab(wu.Tabs["registration"].MakeHTML("Registration", "2"))
		return
	}
}

func updateRegisterContent(tabC *js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}

	url := wu.GetImmsrvURL()
	regRoles := id.GetRegRoles(url)
	if len(regRoles) == 0 {
		return
	}

	role := id.GetRole()
	
	roleOptions := map[string]string{
		ballotcli.ROLE_AdminVoterReg: "Administrator for voter registration",
		ballotcli.ROLE_AdminOfficial: lb.OfficialAdminRole,
		ballotcli.ROLE_Voter: "Voter",
		ballotcli.ROLE_ElectionOfficial: lb.OfficialRole,
	}

	var enableOpt []string
	if regRoles[0] == "*" && role == "GeneralUser" {
		enableOpt = append(enableOpt, ballotcli.ROLE_AdminVoterReg, ballotcli.ROLE_AdminOfficial)
	}
	switch role {
	case ballotcli.ROLE_AdminVoterReg:
		enableOpt = append(enableOpt, ballotcli.ROLE_Voter)
	case ballotcli.ROLE_AdminOfficial:
		enableOpt = append(enableOpt, ballotcli.ROLE_ElectionOfficial)
	}

	selOptions := ""
	for _, optName := range enableOpt {
		selOptions += `<option value="`+optName+`">`+roleOptions[optName]+`</option>`
	}
	
	
	html := `
      <div class="cert-area">
	    <div class="row">
          <div class="cert-item"><label for="ballotRole" id="ballotRoleLable">`+lb.Role+`</lable></div>
          <div class="cert-input">
            <select id="ballotRole">` + selOptions + `</select>
          </div>
        </div>
	    <div class="row" id="registerNameArea">
          <div class="cert-item"><label for="registerName" id="registerNameLabel">Username</label></div>
          <div class="cert-input"><input type="text" id="registerName" value=""></div>
        </div>
        <div class="row">
          <div class="cert-item"><label for="registerSecret">Secret</label></div>
          <div class="cert-input"><input type="text" id="registerSecret"></div>
        </div>
        <div class="row">
          <div class="immDSBtn"><button onClick="register()" id="registerButton">Register</button></div>
        </div>
        <div class="row">
          <p id="registerResult"></p>
        </div>
      </div>`
	
	tabC.Set("innerHTML", html)
}

func register(this js.Value, in []js.Value) interface{}{
	doc := js.Global().Get("document")
	url := wu.GetImmsrvURL()
	
	result := doc.Call("getElementById", "registerResult")
	resultMsg := "Success"

	usernameObj := doc.Call("getElementById", "registerName")
	secretObj := doc.Call("getElementById", "registerSecret")

	ballotRoleSel := doc.Call("getElementById", "ballotRole").Get("value").String()
	
	go func() {
		defer func() {
			result.Set("innerHTML", resultMsg)
		}()
		
		id, err := websto.GetCurrentID()
		if err != nil {
			resultMsg = err.Error()
			return
		}

		regUserReq := getBallotUserRegUserReq(ballotRoleSel)
		if regUserReq == nil {
			resultMsg = "Unknown role: " + ballotRoleSel
			return
		}

		err = id.CheckAndAddAffiliation(url, regUserReq.Affiliation)
		if err != nil {
			resultMsg = err.Error()
			return
		}
	
		err = webcli.RegisterAppUserCA(id, regUserReq, &usernameObj, &secretObj)
		if err != nil {
			resultMsg = err.Error()
			return
		}
		
		return // success
	}()

	return nil
}

func getBallotUserRegUserReq(role string) (req *immclient.RegistrationRequest) {
	switch role {
	case "AdminVoterReg":
		req = &immclient.RegistrationRequest{
			Attributes: []immclient.Attribute{
				immclient.Attribute{Name: "imm.Role.AdminVoterReg",  Value: "true", ECert: true},
				immclient.Attribute{Name: "hf.Registrar.Roles", Value: "adminVoterReg,voterReg,voter", ECert: false},
				//				immclient.Attribute{Name: "hf.AffiliationMgr", Value: "1", ECert: false},				
				immclient.Attribute{Name: "hf.Registrar.Attributes", Value: "imm.Role.VoterReg,imm.Role.Voter,imm.AuthParam,imm.VoterState,hf.Registrar.Roles,hf.Registrar.Attributes", ECert: false},
			},
			Affiliation: "voter",
			Type: "adminVoterReg",
		}
		/*
	case "VoterReg":
		req = &immclient.RegistrationRequest{
			Attributes: []immclient.Attribute{
				immclient.Attribute{Name: "imm.Role.VoterReg", Value: "true", ECert: true},
				immclient.Attribute{Name: "hf.Registrar.Roles", Value: "voterReg,voter", ECert: false},
				immclient.Attribute{Name: "hf.Registrar.Attributes", Value: "imm.VoterState", ECert: false},
			},
			//			Affiliation: "voter.fedVoter",
			Type: "voterReg",
		}
*/
	case "Voter":
		req = &immclient.RegistrationRequest{
			Name: "@voter", // group name
			Attributes: []immclient.Attribute{
				immclient.Attribute{Name: "imm.Role.Voter", Value: "true", ECert: true},
				immclient.Attribute{Name: "imm.VoterState", Value: "registered", ECert: false},
			},
			Type: "voter",
		}		
	case "AdminOfficial":
		req = &immclient.RegistrationRequest{
			Attributes: []immclient.Attribute{
				immclient.Attribute{Name: "imm.Role.AdminOfficial", Value: "true", ECert: true},
				immclient.Attribute{Name: "hf.Registrar.Roles", Value: "client", ECert: false},
				immclient.Attribute{Name: "hf.Registrar.Attributes", Value: "imm.Role.ElectionOfficial,imm.Role.BallotBox", ECert: false},
			},
			Affiliation: "ElectionOfficial",
			Type: "client",
		}
	case "ElectionOfficial":
		req = &immclient.RegistrationRequest{
			Attributes: []immclient.Attribute{
				immclient.Attribute{Name: "imm.Role.ElectionOfficial", Value: "true", ECert: true},
			},
			Type: "client",
		}
	}

	return
}

func updateEnrollContent(tabC *js.Value) {
	jpkiF := webjpki.IsAvailable()
	authMethodHidden := " hidden"

	if jpkiF {
		authMethodHidden = ""
	}
	
	html := `
      <div class="cert-area">
      <div class="row"`+authMethodHidden+`>
        <div class="cert-item"><label for="type">Authentication method</label></div>
        <div class="cert-input">
          <select id="voterAuthMethod" onchange="selectedVoterAuthMethod()">
            <option value="pass">Username and password</option>`
	if jpkiF {
		html += `<option value="JPKI">JPKI card</option>`
	}
	html += `
          </select>
        </div>
      </div>
      <div id="userAttrArea"></div>
      <div class="row">
        <div class="immDSBtn">
          <button onclick="registerVoter()" id="registerVoterBtn">Register</button>
        </div>
      </div>
      </div>`

	tabC.Set("innerHTML", html)

	doc := js.Global().Get("document")
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
	url := wu.GetImmsrvURL()
	doc := js.Global().Get("document")
	authMethodSel := doc.Call("getElementById", "voterAuthMethod")
	authMethod := authMethodSel.Get("value").String()

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
				wu.VisibleMsgBox("The specified name or password is incorecct.")
				print("log: "+ err.Error() + "\n")
				return
			}

			// save a user key-pair into the local storage
			websto.StoreKeyPair(voterName, id)
			websto.SetCurrentUsername(id.Name)

			refreshVoterContent()
		case "JPKI":
			makeExportAuthCertBox()
		default:
			wu.VisibleMsgBox("Unknown authentication method")
		}
	}()
	return nil
}

func makeExportAuthCertBox() {
	header := `  <label>You will send your certificate for authentication. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	header += `  <input type="number" id="authPIN">`
	
	webjpki.GetAuthCertPIN = func() string {
		doc := js.Global().Get("document")
		return doc.Call("getElementById", "authPIN").Get("value").String()		
	}
	
	wu.MakeReqBox("exportAuthCert", header, "", true, true)
}

func exportAuthCertOK(in []js.Value) {
	errMsg := webjpki.ExportAuthCertOK(in)
	if errMsg != "" {
		wu.VisibleMsgBox(errMsg)
		return
	}

	makeExportSignCertBox() // success
}

func makeExportSignCertBox() {
	header := `  <label>You will send your certificate for signature. This certificate will be authenticated by Immutable Server. Please enter your PIN.</label>`
	header += `  <input type="text" id="signPIN">`

	webjpki.GetSignCertPIN = func() string {
		doc := js.Global().Get("document")
		return doc.Call("getElementById", "signPIN").Get("value").String()
	}
	
	wu.MakeReqBox("exportSignCert", header, "", true, true)
}

func exportSignCertOK(in []js.Value) {
	errMsg := webjpki.ExportSignCertOK(in , ballotcli.VoterGrpForJPKI)
	if errMsg != "" {
		wu.VisibleMsgBox(errMsg)
		return
	}

	wu.CloseReqBox(nil)
	refreshVoterContent()
}

func updateVoteContent(tabC *js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		return
	}
	
	role := id.GetRole()
	if role != ballotcli.ROLE_Voter {
		return
	}
	
	html := makeResultVoteContent(id)
	if html == "" {
		html += makeVoteContent(id)
	}
	tabC.Set("innerHTML", html)
}

var cachePapers *[]ballotcli.Paper = nil
func makeVoteContent(id *immclient.UserID) (html string) {
	url := wu.GetImmsrvURL()

	state, err := ballotcli.GetMyVoterState(id, url)
	if err != nil {
		html = err.Error()
		return
	}

	if state != "registered" {
		if state != "voted" {
			html = "invalid state: " + state
			return
		}

		html = "<label>You have already voted.</lable>"
		return
	}
	
	papers, err := ballotcli.GetPaper(id, url)
	if err != nil {
		html = err.Error()
		return
	}
	cachePapers = papers

	html = `
      <div class="cert-area">
        <div class="row">
          <div class="cert-itme"><label>Papers</label>
        </div>`
	for i, paper := range *papers {
		paperNo := "paper" + strconv.Itoa(i)
		html += `
        <div class="row">
          <div class="cert-itme"><label>`+ strconv.Itoa(i+1) + ". " + paper.Description + `</label>
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
		case ballotcli.PAPER_METHOD_APPROVAL:
			for j, candidate := range paper.Candidates {
				candidateNo := paperNo + "." + strconv.Itoa(j)
				html += `<div class="row">`
				html += `  <div class="cert-item"><label>` + candidate.Name + "</label></div>"
				html += `  <div class="cert-input"><label class="checkbox">approval<input type="checkbox" id="` + candidateNo + `"><span class="checkmark"></span></label></div>`
				html += `</div>`
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
		case ballotcli.PAPER_METHOD_OPINION:
			opinionID := paperNo + ".opinion"
			maxLength := paper.Option[0]
			html += `<div class="row">`
			html += `  <input type="text" id="`+opinionID+`" maxlength="`+maxLength+`">`
			html += `</div>`
		default:
			html = "unexpected paper type: " + paper.Method
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
	return
}

func vote(this js.Value, in []js.Value) interface{} {
	if cachePapers == nil {
		wu.VisibleMsgBox("Failed to get paper templates")
		return nil
	}

	gl := js.Global()
	doc := gl.Get("document")
	
	header := `
      <div class="cert-area">
        <div class="row">
          <div class="cert-itme"><label>You will vote the following papers. Are you sure?</label>
        </div>`

	for i, paper := range *cachePapers {
		paperNo := "paper" + strconv.Itoa(i)
		header += `<div class="row">`
		header += `  <lable>`+ strconv.Itoa(i+1) + ". " + paper.Description + `</label>`
		header += `</div>`

		switch paper.Method {
		case ballotcli.PAPER_METHOD_RADIO:
			selectedCandidate := doc.Call("querySelector", "input[name=\""+paperNo+"\"]:checked").Get("value").String()
			selectedNo, err := strconv.Atoi(strings.TrimPrefix(selectedCandidate, paperNo+"."))
			if err != nil {
				wu.VisibleMsgBox("unexpected string")
				return nil
			}
			
			candidate := paper.Candidates[selectedNo]
			header += `<div class="row">`
			header += candidate.Name
			header += "</div>"

			// clear candidates and select a candidate
			for j := 0; j < len(paper.Candidates); j++ {
				(*cachePapers)[i].Candidates[j].VoterInput = ""
			}
			(*cachePapers)[i].Candidates[selectedNo].VoterInput = "selected"
		case ballotcli.PAPER_METHOD_APPROVAL:
			for j, candidate := range paper.Candidates {
				candidateNo := paperNo + "." + strconv.Itoa(j)
				state := "disapproval"
				if doc.Call("getElementById", candidateNo).Get("checked").Bool() {
					state = "approval"
				}
				
				header += `<div class="row">`
				header += `  <label>` + candidate.Name + ": " + state + "</label>"				
				header += `</div>`

				(*cachePapers)[i].Candidates[j].VoterInput = state
			}
		case ballotcli.PAPER_METHOD_DISAPPROVAL:
			for j, candidate := range paper.Candidates {
				candidateNo := paperNo + "." + strconv.Itoa(j)
				state := "approval"
				if doc.Call("getElementById", candidateNo).Get("checked").Bool() {
					state = "disapproval"
				}
				
				header += `<div class="row">`
				header += `  <label>` + candidate.Name + ": " + state + "</label>"
				header += `</div>`

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
					wu.VisibleMsgBox("unexpected string")
					return nil
				}
				candidate := paper.Candidates[selectedNo]

				header += `<div class="row">`
				header += ` <label>Selected rank No.`+strconv.Itoa(k)+": "+ candidate.Name + "</label>"
				header += `</div>`

				scores[selectedNo] += 1 + (noOfCandidates - k)
			}

			for j := 0; j < noOfCandidates; j++ {
				(*cachePapers)[i].Candidates[j].VoterInput = strconv.Itoa(scores[j])
			}
		case ballotcli.PAPER_METHOD_OPINION:
			opinionStr := doc.Call("getElementById", paperNo+".opinion").Get("value").String()
			
			header += `<div class="row">`
			header += `  <label>`+opinionStr+`</label>`
			header += `</div>`
			
			(*cachePapers)[i].Option = append((*cachePapers)[i].Option, opinionStr)
		}
		header += "<br>"
	}
	header += `<div class="row">`
	footer := `</div>` // row
	footer += `<div class="row">`
	footer +=   `<p id="voteErrMsg"></p>`
	footer += `</div>`
	footer += `</div>` // cert-area

	wu.MakeReqBox("vote", header, footer, true, true)
	return nil
}

func voteOK(in []js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		wu.VisibleMsgBox("failed to get your ID: " + err.Error())
		return
	}
	url := wu.GetImmsrvURL()

	wu.VisibleSimpleMsgBox("Voting...")
	err = ballotcli.Vote(id, url, cachePapers)
	if err != nil {
		// wu.VisibleMsgBox(err.Error())
		gl := js.Global()
		doc := gl.Get("document")
		voteErrMsg := doc.Call("getElementById", "voteErrMsg")
		voteErrMsg.Set("innerHTML", err.Error())
		return
	}

	refreshVoterContent()
	wu.CloseReqBox(nil)
	return // success
}

func updateCreateBallotBoxContent(tabC *js.Value) {
	html := ""
	defer func() {
		tabC.Set("innerHTML", html)
	}()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		html = "Unknown user"
		return
	}
	
	url := wu.GetImmsrvURL()
	storageGrpList, err := id.ListAvailableStorageGroup(url)
	if err != nil || len(storageGrpList) == 0 {
		html = "Not found avaliable storage group"
		return
	}
	
	html = `
<div class="cert-area">
  <div class="row">
    <label>`+lb.SelectBox+`</label>
  </div>
  <div class="row">
    <div class="cert-item"><label for="storageGrp">Storage group</label></div>
    <div class="cert-input">
      <select id="recordStorageGrp">`
	for _, storageGrp := range storageGrpList {
		html += `<option value="`+storageGrp+`">`+storageGrp+`</option>`
	}
	html += `
      </select>
    </div>
    <div class="row">
      <div class="immDSBtn">
        <button onclick="createBox()" id="createBoxBtn">`+lb.CreateBoxBtn+`</button>
      </div>
    </div>
</div>`

}

func createBox(this js.Value, in[]js.Value) interface{} {
	header := `<dev class="row"><label>`+lb.SealBox+`</label></div>`
	wu.MakeReqBox("createBox", header, "", true, true)
	return nil
}

func createBoxOK(in []js.Value) {
	gl := js.Global()
	doc := gl.Get("document")
	storageGrpSel := doc.Call("getElementById", "recordStorageGrp")
	storageGrp := storageGrpSel.Get("value").String()
	
	id, err := websto.GetCurrentID()
	if err != nil {
		wu.VisibleMsgBox("Failed to get your ID")
		return
	}

	url := wu.GetImmsrvURL()
	wu.VisibleSimpleMsgBox("Creating a box...")
	err = ballotcli.CreateBox(id, url, storageGrp)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}
	
	wu.VisibleMsgBox("Success")
	return // success
}

var cachePaperTemp *ballotcli.Paper
var cachePaperTemps []ballotcli.Paper

func updateSetPapersContent(tabC *js.Value) {
	if cachePaperTemp == nil {
		cachePaperTemp = &ballotcli.Paper{}
	}

	enableMethods := []string{ballotcli.PAPER_METHOD_RADIO, ballotcli.PAPER_METHOD_APPROVAL,
		ballotcli.PAPER_METHOD_DISAPPROVAL, ballotcli.PAPER_METHOD_RANK}
	if SurveyModeF {
		enableMethods = append(enableMethods, ballotcli.PAPER_METHOD_OPINION)
	}
	
	selMethods := ""
	selected := " selected"
	for _, method := range enableMethods {
		selMethods += `<option value="`+method+`"`+selected+`>`+methodStr[method]+`</option>`
		selected = ""
	}
	
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
            <select id="votingMethod" onchange="selectedVotingMethod()">`+selMethods+`
            </select>
          </div>
        </div>

        <div id="paperMethodArea">
        </div>

        <br>
        <div class="row">
          <div class="immDSBtn"><button onclick="addPaperTemplate()" id="addPaperBtn">`+lb.AddPaperBtn+`</button></div>
        </div>
        <div id="listPaperTemplatesArea"></div>
      </div>`
	
	tabC.Set("innerHTML", html)
	doc := js.Global().Get("document")
	votingMethodSel := doc.Call("getElementById", "votingMethod")
	votingMethodSel.Call("onchange")
}

func selectedVotingMethod(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")
	method := doc.Call("getElementById", "votingMethod").Get("value").String()
	paperMethodArea := doc.Call("getElementById", "paperMethodArea")

	html := ""
	defer func() {
		paperMethodArea.Set("innerHTML", html)
	}()
	
	if method == ballotcli.PAPER_METHOD_OPINION {
		html += `
        <div class="row">
          <div class="cert-item"><label>The maximum number of characters in this opinion: </label></div>
		  <div class="cert-input"><input type="number" min="80" id="maxCharOpinion" value="80"></div>
        </div>`


		return nil
	}

	html += `
        <div id="listCandidatesArea"></div>
        <div class="row">
          <div class="cert-item"><label for="candidateName">Candidate name: </label></div>
          <div class="cert-input"><input type="text" id="candidateName"></div>
        </div>
        <div class="row">
          <div class="immDSBtn"><button onclick="addCandidate()" id="addCandidateBtn">Add a candidate</button></div>
        </div>`
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

	if cachePaperTemp.Method == ballotcli.PAPER_METHOD_OPINION {
		maxChars := doc.Call("getElementById", "maxCharOpinion").Get("value").String()
		cachePaperTemp.Option = append(cachePaperTemp.Option, maxChars)
	} else {
		if cachePaperTemp.Candidates == nil || len(cachePaperTemp.Candidates) <= 0 {
			// no candidate
			return nil
		}
	}
	
	cachePaperTemps = append(cachePaperTemps, *cachePaperTemp)
	updateListPaperTemps()
	cachePaperTemp = &ballotcli.Paper{} // new paper
	return nil
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

		if paper.Method == ballotcli.PAPER_METHOD_OPINION {
			html += `
          <div class="row">
            <div class="cert-item"><label>The maximum number of characters is: </label></div>
            <div class="cert-input"><label>`+paper.Option[0]+`</label></div>
          </div>`
			continue
		}
		
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
	url := wu.GetImmsrvURL()
	go func() {
		wu.VisibleSimpleMsgBox("Storing templates...")
		id, _ := websto.GetCurrentID()
		err := ballotcli.SetPaper(id, url, &cachePaperTemps)
		if err != nil {
			wu.VisibleMsgBox(err.Error())
			return
		}

		wu.VisibleMsgBox("Success") // visible success message
		return
	}()
	return nil
}

func updateOpenBallotBoxContent(tabC *js.Value) {
	html := `<div class="cert-area">`
	html += `  <div class="row"><div class="immDSBtn">`
	html += `    <button onclick="openBallotBox()" id="openBallotBoxBtn">`+lb.OpenBoxBtn+`</button>`
	html += `  </div></div>`
	html += "</div>"
	tabC.Set("innerHTML", html)
}

func openBallotBox(this js.Value, in []js.Value) interface{} {
	header := `<label>`+lb.OpenBox+`</label>`
	wu.MakeReqBox("openBallotBox", header, "", true, true)
	return nil
}
	
func openBallotBoxOK(in []js.Value) {
	go func() {
		wu.VisibleSimpleMsgBox(lb.OpenBoxProgress)
		id, _ := websto.GetCurrentID()
		url := wu.GetImmsrvURL()
		err := ballotcli.OpenBallotBox(id, url)
		if err != nil {
			wu.VisibleMsgBox(err.Error())
			return
		}

		wu.VisibleMsgBox("Success")
		return
	}()
}

func updateRecordSealPubKeyContent(tabC *js.Value) {
	html := `
<div class="cert-area">
  <div class="row"><label>`+lb.RecordPubKey+`</label></div>
  <div class="row"><div class="immDSBtn">
      <button onclick="recordSealPubKey()" id="recordSealPubKeyBtn">Record</button>
  </div></div>
</div>`
	tabC.Set("innerHTML", html)
}


func recordSealPubKey(this js.Value, in []js.Value) interface{} {
	header := `<div class="row"><label>You will record your public key to Immutable Storage.</label></div>`
	wu.MakeReqBox("recordSealPubKey", header, "", true, true)
	return nil
}

func recordSealPubKeyOK(in []js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		wu.VisibleMsgBox("Failed to get your ID")
		return
	}

	wu.VisibleSimpleMsgBox("Recording...")
	url := wu.GetImmsrvURL()
	err = ballotcli.SetSealPubKey(id, url)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}

	wu.VisibleMsgBox("Success")
	return // success
}

func updateSetPollTimesContent(tabC *js.Value) {
	now := time.Now()
	nowStr := now.Format("2006-01-02T15:04:05")
	html := `
      <div class="cert-area">
        <div class="row">
          <label>You will set poll opening and closing times.</label>
        </div>

        <div class="row">
          <div class="cert-item"><label>Opening time:</label></div>
          <div class="cert-input"><input type="datetime-local" id="openingTime" step="1" value="`+nowStr+`" min="`+nowStr+`"></div>
        </div>

        <div class="row">
          <div class="cert-item"><label>Closing time:</label></div>
          <div class="cert-input"><input type="datetime-local" id="closingTime" step="1" value="`+nowStr+`" min="`+nowStr+`"></div>
        </div>

        <div class="row">
          <div class="immDSBtn">
            <button onclick="setPollTimesBtns(event)" name="OK">OK</button>
          </div>
        </div>
      </div>`

	tabC.Set("innerHTML", html)
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
	
func setPollTimesBtns(this js.Value, in []js.Value) interface{} {
	doc := js.Global().Get("document")	

	offset := curTimeOffset()	
	reqPollTimes := &ballotcli.PollTimes{
		OpeningTime: doc.Call("getElementById", "openingTime").Get("value").String()+offset, // RFC3339 format
		ClosingTime: doc.Call("getElementById", "closingTime").Get("value").String()+offset, // RFC3339 format
	}

	go func() {
		wu.VisibleSimpleMsgBox("Setting...")
		id, _ := websto.GetCurrentID()
		url := wu.GetImmsrvURL()
		err := ballotcli.SetPollTimes(id, url, reqPollTimes)
		if err != nil {
			wu.VisibleMsgBox(err.Error())
			return
		}

		// success
		wu.VisibleMsgBox("Success")
		return
	}()
	
	return nil
}

func updateCountVotesContent(tabC *js.Value) {
	html := `
<div class="cert-area">
  <div class="row"><label>You will count votes.</label></div>
  <div class="row">
    <div class="immDSBtn">
      <button onclick="countVotes()" id="countVotesBtn">Count votes</button>
    </div>
  </div>
</div>
`
	tabC.Set("innerHTML", html)
}

func countVotes(this js.Value, in []js.Value) interface{} {
	header := `<label>`+lb.CountVotes+`</label>`
	wu.MakeReqBox("countVotes", header, "", true, true)
	return nil
}

func countVotesOK(in []js.Value) {
	id, err := websto.GetCurrentID()
	if err != nil {
		wu.VisibleMsgBox("Failed to get your ID")
		return
	}

	wu.VisibleSimpleMsgBox("Counting...")
	url := wu.GetImmsrvURL()
	err = ballotcli.CountVotes(id, url)
	if err != nil {
		wu.VisibleMsgBox(err.Error())
		return
	}
	
	wu.VisibleMsgBox("Success")
	return
}

func updateSelectVoterTypeContent(tabC *js.Value) {
	html := `
      <div class="cert-area">
        <div class="row">
          <div class="cert-item"><label for="vooterAuthType">Voter type</label></div>
          <div class="cert-input">
            <select id="voterAuthType" onchange="selectedVoterType()">
              <option value="CAVoter">Select votors marked voter on CA DB</option>
              <option value="LDAPVoter">Select voters from the LDAP</option>
              <option value="GraphVoter">Select voters from MS Graph (OAuth2)</option>
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
	
	tabC.Set("innerHTML", html)
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
            <div class="cert-item"><label for="fedGrpName">Federation group name</label></div>
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
	case "GraphVoter":
		id, err := websto.GetCurrentID()
		org := ""
		if err == nil {
			org, _ = id.GetIssuerOrg()
		}
		html += `
          <div class="row">
            <div class="cert-item"><label for="groupName">Group name</label></div>
            <div class="cert-input"><input type="text" id="groupName" value="group1"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="clientID">Client ID</label></div>
            <div class="cert-input"><input type="text" id="clientID"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="secretValue">Client secret value</label></div>
            <div class="cert-input"><input type="text" id="secretValue"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="allowPrincipalDomains">Allow principal domains</label></div>
            <div class="cert-input"><input type="text" id="allowPrincipalDomains" value="example.com"></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="redirectURL">Redirect URL</label></div>
            <div class="cert-input"><input type="text" id="redirectURL" value="https://www.`+org+`/graphcallback" readonly></div>
		  </div>
          <div class="row">
            <div class="cert-item"><label for="Login URL">Login URL</label></div>
            <div class="cert-input"><input type="text" id="loginURL" value="https://www.`+org+`/graphcallback/login/group1" readonly></div>
		  </div>`
	case "JPKIVoter":
		html += `
          <div class="row">
            <div class="cert-item"><label for="fedGrpName">Federation group name</label></div>
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
		"GraphVoter": selectVoterOAuthGraph,
		"JPKIVoter": selectVoterJPKI,
	}

	url := wu.GetImmsrvURL()
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

func selectVoterOAuthGraph(id *immclient.UserID, url string) error {
	doc := js.Global().Get("document")
	authParamS := &struct{
		GroupName string
		ClientID string
		SecretValue string
		AllowDomains string
		ReqPath string
	}{
		GroupName: doc.Call("getElementById", "groupName").Get("value").String(),
		ClientID: doc.Call("getElementById", "clientID").Get("value").String(),
		SecretValue: doc.Call("getElementById", "secretValue").Get("value").String(),
		AllowDomains: doc.Call("getElementById", "allowPrincipalDomains").Get("value").String(),
		ReqPath: js.Global().Get("location").Get("pathname").String(),
	}
	authParamRaw, err := json.Marshal(authParamS)
	if err != nil {
		return errors.New("failed to get authentication parameters: " + err.Error())
	}
	org, _ := id.GetIssuerOrg()
	loginURL := "https://www."+org+"/graphcallback/login/"+authParamS.GroupName
	doc.Call("getElementById", "loginURL").Set("value", loginURL)

	req := &ballotcli.SelectVoterRequest{
		AuthType: "OAUTH_GRAPH",
		AuthParam: authParamRaw,
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
		return errors.New("invalid comparison symbol")
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

func makeResultVoteContent(id *immclient.UserID) string {
	url := wu.GetImmsrvURL()
	papers, err := ballotcli.GetResultVote(id, url)
	if err != nil {
		return ""
	}

	html := `
      <div class="cert-area">
        <div class="row">
          <label>`+lb.Result+`</label>
        </div>`
	for pN, paper := range *papers {
		html += `
        <div class="row">
          <label>`+strconv.Itoa(pN+1)+`. `+paper.Description+` (Voting method: `+methodStr[paper.Method]+`)</label>
        </div>`

		if paper.Method == ballotcli.PAPER_METHOD_OPINION {
			if len(paper.Option) < 2 {
				html += `<div class="row">`
				html += `  <label>No opinion</label>`
				html += `</div>`
				html += "<br>"				
				continue
			}

			html += `<table>`
			html += `  <tr>`
			html += `    <td>#</td><td>Opinion</td>`
            html += `  </tr>`
			for i := 1; i < len(paper.Option); i++ {
				html += `<tr>`
				html += `  <td>`+strconv.Itoa(i)+`</td>`
				html += `  <td>`+paper.Option[i]+`</td>`
				html += `</tr>`
			}
			html += `<table>`
			html += "<br>"
			continue
		}

		itemCount := "Count"
		if paper.Method == ballotcli.PAPER_METHOD_RANK {
			itemCount = "Score (more is better)"
		}

		html += `
        <table>
          <tr>
		    <td>#</td><td>Candidate name</td><td>`+itemCount+`</td>
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
		html += "<br>"
	}
	html += `
      </div>`

	return html // success
}
