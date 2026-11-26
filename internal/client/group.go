package client

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"

	"github.com/gallbotond/vpncell/internal/brand"
)

// Group membership as seen from a failed connect() with EACCES (issue #9).
type membership int

const (
	memberActive   membership = iota // this process has the group: the socket's permissions are wrong
	memberInactive                   // in the group database, but not in this login session
	memberNone                       // not a member
	groupMissing                     // the group does not exist
)

// diagnose decides the case from the group database entry
// ("name:x:gid:user1,user2"; empty if the group does not exist), the
// user's name and primary gid, and the groups of this process.
func diagnose(groupEntry, username string, primaryGID int, procGIDs []int) membership {
	f := strings.Split(strings.TrimSpace(groupEntry), ":")
	if len(f) < 3 {
		return groupMissing
	}
	gid, err := strconv.Atoi(f[2])
	if err != nil {
		return groupMissing
	}
	for _, g := range procGIDs {
		if g == gid {
			return memberActive
		}
	}
	if primaryGID == gid {
		return memberInactive
	}
	if len(f) >= 4 {
		for _, m := range strings.Split(f[3], ",") {
			if m == username && m != "" {
				return memberInactive
			}
		}
	}
	return memberNone
}

func membershipMessage(m membership, path string) string {
	g := brand.Group
	head := "permission denied on " + path + ": "
	switch m {
	case memberInactive:
		return head + fmt.Sprintf("you are in the %q group, but this login session started before you were added.\n"+
			"Log out of the desktop and in again (a new terminal is not enough), or for this shell only: newgrp %s   (or: sg %s -c '%s list')",
			g, g, g, brand.Name)
	case memberNone:
		return head + fmt.Sprintf("you are not in the %q group: sudo usermod -aG %s $USER, then log out and in again", g, g)
	case groupMissing:
		return head + fmt.Sprintf("the %q group does not exist (is the %s package installed?)", g, brand.Name)
	}
	return head + fmt.Sprintf("this process is in the %q group, so check the socket's owner and mode: ls -l %s", g, path)
}

// groupHint looks up the facts for diagnose. getent covers NSS sources
// (LDAP, sssd) as well as /etc/group.
func groupHint(path string) string {
	entry := ""
	if out, err := exec.Command("getent", "group", brand.Group).Output(); err == nil {
		entry = string(out)
	} else if b, err := os.ReadFile("/etc/group"); err == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, brand.Group+":") {
				entry = l
				break
			}
		}
	}
	name, primary := os.Getenv("USER"), -1
	if u, err := user.LookupId(strconv.Itoa(os.Getuid())); err == nil {
		name = u.Username
		primary, _ = strconv.Atoi(u.Gid)
	} else if out, err := exec.Command("getent", "passwd", strconv.Itoa(os.Getuid())).Output(); err == nil {
		if f := strings.Split(strings.TrimSpace(string(out)), ":"); len(f) >= 4 {
			name = f[0]
			primary, _ = strconv.Atoi(f[3])
		}
	}
	gids, _ := os.Getgroups()
	gids = append(gids, os.Getegid())
	return membershipMessage(diagnose(entry, name, primary, gids), path)
}
