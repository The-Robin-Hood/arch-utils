package main

import "fmt"

type DiskDetails struct {
	Type, Total, Used, Free string
}

func sizeToString(size uint64) (str string) {
	b := float64(size)

	switch {
	case size >= 1<<60:
		str = fmt.Sprintf("%.1fE", b/(1<<60))
	case size >= 1<<50:
		str = fmt.Sprintf("%.1fP", b/(1<<50))
	case size >= 1<<40:
		str = fmt.Sprintf("%.1fT", b/(1<<40))
	case size >= 1<<30:
		str = fmt.Sprintf("%.1fG", b/(1<<30))
	case size >= 1<<20:
		str = fmt.Sprintf("%.1fM", b/(1<<20))
	case size >= 1<<10:
		str = fmt.Sprintf("%.1fK", b/(1<<10))
	default:
		str = fmt.Sprintf("%dB", size)
	}
	return
}

var fsTypeMap = map[int64]string{
	0xEF53:     "EXT2 / EXT3 / EXT4",
	0x58465342: "XFS",
	0x9123683E: "Btrfs",
	0x52654973: "ReiserFS",
	0x5346544E: "NTFS",
	0xF995E849: "ZFS",
	0x2FC12FC1: "ZFS (alt)",
	0x65735546: "FUSE",
	0x01021994: "TMPFS",
	0x28CD3D45: "CRAMFS",
	0x73717368: "SquashFS",
	0x4244:     "HFS",
	0x482B:     "HFS+",
	0x41504653: "APFS",
	0x6969:     "NFS",
	0xFF534D42: "CIFS / SMB",
	0x4D44:     "FAT",
	0x4006:     "FAT32",
	0xE0F5E1E2: "EXFAT",
	0x9660:     "ISO 9660",
	0x15013346: "UDF",
}
