package networktest

import (
	"netscan/internal/network"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseCidr_ResultBounds(t *testing.T) {
	addrParser := network.NewAddrParser()

	t.Run("parse 192.168.1.0/24", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("192.168.1.0/24")
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.1", addrParser.GetHostsFirst().String())
		assert.Equal(t, "192.168.1.254", addrParser.GetHostsLast().String())
	})

	t.Run("parse 192.168.1.0/31", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("192.168.1.0/31")
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.0", addrParser.GetHostsFirst().String())
		assert.Equal(t, "192.168.1.1", addrParser.GetHostsLast().String())
	})

	t.Run("parse 192.168.1.5/32", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("192.168.1.5/32")
		require.NoError(t, err)
		assert.Equal(t, "192.168.1.5", addrParser.GetHostsFirst().String())
		assert.Equal(t, "192.168.1.5", addrParser.GetHostsLast().String())
	})

	t.Run("parse 10.0.0.0/30", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("10.0.0.0/30")
		require.NoError(t, err)
		assert.Equal(t, "10.0.0.1", addrParser.GetHostsFirst().String())
		assert.Equal(t, "10.0.0.2", addrParser.GetHostsLast().String())
	})

	t.Run("parse 10.6.5.7/28", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("10.6.5.7/28")
		require.NoError(t, err)
		assert.Equal(t, "10.6.5.1", addrParser.GetHostsFirst().String())
		assert.Equal(t, "10.6.5.14", addrParser.GetHostsLast().String())
	})

	t.Run("parse 192.168.0.0/23", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("192.168.0.0/23")
		require.NoError(t, err)
		assert.Equal(t, "192.168.0.1", addrParser.GetHostsFirst().String())
		assert.Equal(t, "192.168.1.254", addrParser.GetHostsLast().String())
	})

	t.Run("parse 2001:db8::/64", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("2001:db8::/64")
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::", addrParser.GetHostsFirst().String())
		assert.Equal(t, "2001:db8::ffff:ffff:ffff:ffff", addrParser.GetHostsLast().String())
	})

	t.Run("parse fe80::/10", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("fe80::/10")
		require.NoError(t, err)
		assert.Equal(t, "fe80::", addrParser.GetHostsFirst().String())
		assert.Equal(t, "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff", addrParser.GetHostsLast().String())
	})

	t.Run("parse 2001:db8::/127", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("2001:db8::/127")
		require.NoError(t, err)
		assert.Equal(t, "2001:db8::", addrParser.GetHostsFirst().String())
		assert.Equal(t, "2001:db8::1", addrParser.GetHostsLast().String())
	})

	t.Run("parse ::1/128", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("::1/128")
		require.NoError(t, err)
		assert.Equal(t, "::1", addrParser.GetHostsFirst().String())
		assert.Equal(t, "::1", addrParser.GetHostsLast().String())
	})
}

func TestParseCidr_ResultSequence(t *testing.T) {
	addrParser := network.NewAddrParser()

	t.Run("parse 10.6.5.7/28", func(t *testing.T) {
		err := addrParser.ParseCidrOrAddr("10.6.5.7/28")
		require.NoError(t, err)
		valid := []string{
			"10.6.5.1",
			"10.6.5.2",
			"10.6.5.3",
			"10.6.5.4",
			"10.6.5.5",
			"10.6.5.6",
			"10.6.5.7",
			"10.6.5.8",
			"10.6.5.9",
			"10.6.5.10",
			"10.6.5.11",
			"10.6.5.12",
			"10.6.5.13",
			"10.6.5.14",
		}
		i := 0
		for addr := range addrParser.Hosts() {
			assert.Equal(t, valid[i], addr.String())
			i++
		}
	})
}
