package main

import (
	"fmt"

	"github.com/zalando/go-keyring"
)

func main() {
	fmt.Println(keyring.ErrNoSecret)
}
