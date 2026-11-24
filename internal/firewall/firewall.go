// Package firewall installs the in-namespace nftables ruleset (DESIGN.md
// §14): only lo and the tunnel interface may carry traffic. It is the second
// layer; fail closed holds without it because the namespace has no other
// interface or route.
package firewall

import (
	"fmt"

	"github.com/gallbotond/vpncell/internal/brand"
	"github.com/gallbotond/vpncell/internal/netns"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
)

func ifname(n string) []byte {
	b := make([]byte, 16)
	copy(b, n)
	return b
}

func accept(t *nftables.Table, ch *nftables.Chain, key expr.MetaKey, name string) *nftables.Rule {
	return &nftables.Rule{Table: t, Chain: ch, Exprs: []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ifname(name)},
		&expr.Verdict{Kind: expr.VerdictAccept},
	}}
}

// Install replaces the ruleset in the profile namespace so that only lo and
// tunIf may carry traffic.
func Install(profile, tunIf string) error {
	return netns.Do(profile, func() error {
		c, err := nftables.New()
		if err != nil {
			return err
		}
		removeTable(c)
		t := c.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: brand.NftTable})
		drop := nftables.ChainPolicyDrop
		mk := func(name string, hook *nftables.ChainHook) *nftables.Chain {
			return c.AddChain(&nftables.Chain{Name: name, Table: t, Type: nftables.ChainTypeFilter,
				Hooknum: hook, Priority: nftables.ChainPriorityFilter, Policy: &drop})
		}
		out := mk("output", nftables.ChainHookOutput)
		in := mk("input", nftables.ChainHookInput)
		mk("forward", nftables.ChainHookForward)
		c.AddRule(accept(t, out, expr.MetaKeyOIFNAME, "lo"))
		c.AddRule(accept(t, out, expr.MetaKeyOIFNAME, tunIf))
		c.AddRule(accept(t, in, expr.MetaKeyIIFNAME, "lo"))
		c.AddRule(accept(t, in, expr.MetaKeyIIFNAME, tunIf))
		if err := c.Flush(); err != nil {
			return fmt.Errorf("nftables: %w", err)
		}
		return nil
	})
}

// Remove deletes the ruleset from the profile namespace.
func Remove(profile string) error {
	return netns.Do(profile, func() error {
		c, err := nftables.New()
		if err != nil {
			return err
		}
		if removeTable(c) {
			return c.Flush()
		}
		return nil
	})
}

// Present reports whether the ruleset exists in the namespace.
func Present(profile string) (bool, error) {
	var ok bool
	err := netns.Do(profile, func() error {
		c, err := nftables.New()
		if err != nil {
			return err
		}
		ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
		if err != nil {
			return err
		}
		for _, t := range ts {
			if t.Name == brand.NftTable {
				ok = true
			}
		}
		return nil
	})
	return ok, err
}

func removeTable(c *nftables.Conn) bool {
	ts, err := c.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false
	}
	for _, t := range ts {
		if t.Name == brand.NftTable {
			c.DelTable(t)
			return true
		}
	}
	return false
}
