module github.com/rviscuso/warden

go 1.27

// MPTCP off by default for every listener and dialer: see DESIGN.md §2
// (CVE-2026-98432). internal/netx also turns it off explicitly per listener.
godebug multipathtcp=0
