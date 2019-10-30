// +build windows
package main

import (
	"fmt"
	"log"
	"time"

	"blitter.com/go/xs/xsnet"
)

// Handle pty resizes (notify server side)
func handleTermResizes(conn *xsnet.Conn) {
	var hasStty bool
	curCols, curRows := 0, 0
	_, _, err := GetSize()
	// The above may fail if user doesn't have msys 'stty' util
	// in PATH. GetSize() will log.Error() once here
	if err != nil {
		fmt.Println("[1st GetSize:", err, "]")
		hasStty = false
	} else {
		hasStty = true
	}

	ch := make(chan bool, 1)

	if hasStty {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				ch <- true
				time.Sleep(1 * time.Second)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		rows := 0
		cols := 0
		for range ch {
			// Query client's term size so we can communicate it to server
			// pty after interactive session starts
			cols, rows, err = GetSize()
			if err == nil {
			} else {
				fmt.Println("[GetSize:", err, "]")
			}
			if (curRows != rows) || (curCols != curCols) {
				curRows = rows
				curCols = cols
				if err != nil {
					log.Println(err)
				}
				termSzPacket := fmt.Sprintf("%d %d", curRows, curCols)
				conn.WritePacket([]byte(termSzPacket), xsnet.CSOTermSize)
			}
		}
	}()
	ch <- true // Initial resize
}
