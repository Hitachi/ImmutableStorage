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
	"ballotweb"
)

func main() {
	ballotweb.SurveyModeF = true
	labels := &ballotweb.Labels{
		AppTitle: "Anonymous Survey",
		SetPapersTab: "Survey Question",
		OfficialAdmin: "survey official administrator",
		Official: "survey official",
		OfficialAdminRole: "Administrator for survey official",
		OfficialRole: "Survey Official",
		Role: "Survey role",
		SelectBox: "Please select a storage group to create a survey box",
		CreateBoxBtn: "Create a survey box",
		SealBox: "You will record your public key to seal the survey box during creating its box.",
		AddPaperBtn: "Add a question",
		OpenBoxBtn: "Open the survey box",
		OpenBox: "You will open the survey box.",
		OpenBoxProgress: "Opening the survey box...",
		RecordPubKey: "Please record your public key to seal survey papers.",
		CountVotes: "You will count votes in the survey box.",
		Result: "Survey result",
	}
	
	ch := make(chan struct{}, 0)
	ballotweb.RegisterCallback(labels)
	ballotweb.MakeContent()
	<- ch
}
