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
	labels := &ballotweb.Labels{
		AppTitle: "Secret Ballot",
		SetPapersTab: "Paper Template",
		OfficialAdmin: "election official administrator",
		Official: "election official",
		OfficialAdminRole: "Administrator for election official",
		OfficialRole: "Election Official",
		Role: "Ballot role",
		SelectBox: "Please select a storage group to create a ballot box",
		CreateBoxBtn: "Create a ballot box",
		SealBox: "You will record your public key to seal the ballot box during creating its box.",
		AddPaperBtn: "Add a paper template",
		OpenBoxBtn: "Open the ballot box",
		OpenBox: "You will open the ballot box.",
		OpenBoxProgress: "Opening the ballot box...",
		RecordPubKey: "Please record your public key to seal ballot papers.",
		CountVotes: "You will count votes in the ballot box.",
		Result: "Election result",
	}
	
	ch := make(chan struct{}, 0)
	ballotweb.RegisterCallback(labels)
	ballotweb.MakeContent()
	<- ch
}
