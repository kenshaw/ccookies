// _example/example.go
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/kenshaw/ccookies"
	//_ "github.com/mattn/go-sqlite3"
	_ "modernc.org/sqlite"
)

func main() {
	file := flag.String("file", "/home/"+os.Getenv("USER")+"/.config/vivaldi/Default/Cookies", "file")
	host := flag.String("host", "", "host")
	flag.Parse()
	if err := run(context.Background(), *file, *host); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, file, host string) error {
	cookies, err := ccookies.Read(ctx, file, host)
	if err != nil {
		return err
	}
	for i, cookie := range cookies {
		fmt.Printf("%d:\n", i)
		fmt.Printf("  domain: %s\n", cookie.Domain)
		fmt.Printf("  name: %q\n", cookie.Name)
		fmt.Printf("  expires: %q\n", cookie.Expires)
		fmt.Printf("  path: %q\n", cookie.Path)
		fmt.Printf("  value: %q\n", cookie.Value)
	}
	return nil
}
