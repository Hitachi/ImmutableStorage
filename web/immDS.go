// Copyright Hitachi, Ltd. 2020 All Rights Reserved.
package main

import (
	"immweb"
)

func main() {
	ch := make(chan struct{}, 0)

	immweb.RegisterCallback()
	immweb.MakeFirstTabs()
	
	<- ch
}
