// _example/example.go
package main

import (
	"flag"
	"log"
	"os"

	"github.com/kenshaw/ccookies"
	//_ "github.com/mattn/go-sqlite3"
	_ "modernc.org/sqlite"
)

func main() {
	file := flag.String("file", "/home/"+os.Getenv("USER")+"/.config/vivaldi/Default/Cookies", "file")
	flag.Parse()
	if err := run(*file); err != nil {
		log.Fatal(err)
	}
}

func run(file string) error {
	cookies, err := ccookies.Read(file, "sketchfab.com")
	if err != nil {
		return err
	}
	for i, cookie := range cookies {
		log.Printf("cookie %d: %+v", i, cookie)
	}
	return nil
}
