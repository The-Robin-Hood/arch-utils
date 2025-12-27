package main

import (
	"fmt"
	"os"
	"github.com/jedib0t/go-pretty/v6/table"
	"golang.org/x/sys/unix"
)

func main() {
	var stat unix.Statfs_t
	mountPoint := "/"
	err := unix.Statfs(mountPoint, &stat)
	if err != nil {
		if err != os.ErrPermission {
			fmt.Printf("%s: %s", mountPoint, err)
		}
		stat = unix.Statfs_t{}
	}

	total := uint64(stat.Blocks) * uint64(stat.Bsize)
	free := uint64(stat.Bavail) * uint64(stat.Bsize)
	used := (uint64(stat.Blocks) - uint64(stat.Bfree)) * uint64(stat.Bsize)

	fsType, ok := fsTypeMap[int64(stat.Type)]
	if !ok {
		fsType = "unknown"
	}
	details := DiskDetails{
		Type:  fsType,
		Total: sizeToString(total),
		Used:  sizeToString(used),
		Free:  sizeToString(free),
	}

	tab := table.NewWriter()
	headers := table.Row{"Mount", "Type", "Total", "Free", "Used"}
	tab.AppendHeader(headers)
	row := table.Row{mountPoint, details.Type, details.Total, details.Free, details.Used}
	tab.AppendRow(row)
	tab.SetStyle(table.StyleRounded)
	fmt.Println(tab.Render())
}
