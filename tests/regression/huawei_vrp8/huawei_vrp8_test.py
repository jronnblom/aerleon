# Copyright 2024 Aerleon Project Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Tests for Huawei VRP8 (CE16800) ACL rendering module."""

from absl.testing import absltest

from aerleon.lib import huawei_vrp8, naming, policy
from tests.regression_utils import capture

GOOD_HEADER = """
header {
  comment:: "this is a test acl"
  target:: huawei-vrp8 test-filter
}
"""

GOOD_HEADER_INET6 = """
header {
  comment:: "this is a test ipv6 acl"
  target:: huawei-vrp8 test-filter inet6
}
"""

GOOD_HEADER_MIXED = """
header {
  comment:: "this is a mixed acl"
  target:: huawei-vrp8 test-filter mixed
}
"""

GOOD_TERM_SIMPLE = """
term good-term {
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_DENY = """
term deny-term {
  protocol:: udp
  action:: deny
}
"""

GOOD_TERM_WITH_PORTS = """
term good-term {
  protocol:: tcp
  source-port:: HTTP
  destination-port:: SSH
  action:: accept
}
"""

GOOD_TERM_SOURCE_ADDR = """
term good-term {
  source-address:: SOME_HOST
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_DST_ADDR_V6 = """
term good-term {
  destination-address:: SOME_HOST6
  protocol:: tcp
  action:: accept
}
"""

GOOD_TERM_TCP_ESTABLISHED = """
term good-term {
  protocol:: tcp
  option:: tcp-established
  action:: accept
}
"""

GOOD_TERM_LOGGING = """
term good-term {
  protocol:: tcp
  logging:: true
  action:: accept
}
"""

GOOD_TERM_ICMP = """
term good-term {
  protocol:: icmp
  icmp-type:: echo-request echo-reply
  action:: accept
}
"""

GOOD_TERM_VERBATIM = """
term good-term {
  verbatim:: huawei-vrp8 " rule 5 permit ip source any destination any"
}
"""

GOOD_TERM_COMMENT = """
term good-term {
  comment:: "allow all TCP"
  protocol:: tcp
  action:: accept
}
"""

# Print a info message when a term is set to expire in that many weeks.
EXP_INFO = 2

SUPPORTED_TOKENS = {
    'action',
    'comment',
    'destination_address',
    'destination_address_exclude',
    'destination_port',
    'expiration',
    'icmp_code',
    'icmp_type',
    'stateless_reply',
    'logging',
    'name',
    'option',
    'owner',
    'platform',
    'platform_exclude',
    'protocol',
    'restrict_address_family',
    'source_address',
    'source_address_exclude',
    'source_port',
    'translated',
    'verbatim',
}

SUPPORTED_SUB_TOKENS = {
    'action': {'accept', 'deny', 'reject', 'next', 'reject-with-tcp-rst'},
    'icmp_type': {
        'alternate-address',
        'certification-path-advertisement',
        'certification-path-solicitation',
        'conversion-error',
        'destination-unreachable',
        'echo-reply',
        'echo-request',
        'mobile-redirect',
        'home-agent-address-discovery-reply',
        'home-agent-address-discovery-request',
        'icmp-node-information-query',
        'icmp-node-information-response',
        'information-request',
        'inverse-neighbor-discovery-advertisement',
        'inverse-neighbor-discovery-solicitation',
        'mask-reply',
        'mask-request',
        'information-reply',
        'mobile-prefix-advertisement',
        'mobile-prefix-solicitation',
        'multicast-listener-done',
        'multicast-listener-query',
        'multicast-listener-report',
        'multicast-router-advertisement',
        'multicast-router-solicitation',
        'multicast-router-termination',
        'neighbor-advertisement',
        'neighbor-solicit',
        'packet-too-big',
        'parameter-problem',
        'redirect',
        'redirect-message',
        'router-advertisement',
        'router-renumbering',
        'router-solicit',
        'router-solicitation',
        'source-quench',
        'time-exceeded',
        'timestamp-reply',
        'timestamp-request',
        'unreachable',
        'version-2-multicast-listener-report',
    },
    'option': {'established', 'tcp-established', 'is-fragment', 'fragments'},
}


class HuaweiVRP8Test(absltest.TestCase):
    def setUp(self):
        super().setUp()
        self.naming = naming.Naming()

    def _Render(self, header, term):
        return huawei_vrp8.HuaweiVRP8(
            policy.ParsePolicy(header + term, self.naming), EXP_INFO
        )

    @capture.stdout
    def testSimplePermit(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SIMPLE)
        output = str(acl)
        self.assertIn('rule 5 permit tcp source any destination any', output)
        self.assertNotIn('exit', output)
        print(acl)

    @capture.stdout
    def testSimpleDeny(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_DENY)
        output = str(acl)
        self.assertIn('rule 5 deny udp source any destination any', output)
        print(acl)

    @capture.stdout
    def testWithPorts(self):
        self.naming._ParseLine('HTTP = 80/tcp', 'services')
        self.naming._ParseLine('SSH = 22/tcp', 'services')
        acl = self._Render(GOOD_HEADER, GOOD_TERM_WITH_PORTS)
        output = str(acl)
        self.assertIn('source-port', output)
        self.assertIn('destination-port', output)
        print(acl)

    @capture.stdout
    def testSourceAddress(self):
        self.naming._ParseLine('SOME_HOST = 10.0.0.0/8', 'networks')
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SOURCE_ADDR)
        output = str(acl)
        self.assertIn('source 10.0.0.0', output)
        print(acl)

    @capture.stdout
    def testDstAddressIpv6(self):
        self.naming._ParseLine('SOME_HOST6 = 2001:db8::/32', 'networks')
        acl = self._Render(GOOD_HEADER_INET6, GOOD_TERM_DST_ADDR_V6)
        output = str(acl)
        self.assertIn('destination 2001:db8:: 32', output)
        print(acl)

    @capture.stdout
    def testTcpEstablished(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_TCP_ESTABLISHED)
        output = str(acl)
        self.assertIn('established', output)
        print(acl)

    @capture.stdout
    def testLogging(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_LOGGING)
        output = str(acl)
        self.assertIn('logging', output)
        print(acl)

    @capture.stdout
    def testIpv6Header(self):
        acl = self._Render(GOOD_HEADER_INET6, GOOD_TERM_SIMPLE)
        output = str(acl)
        self.assertIn('acl ipv6 name test-filter advance', output)
        self.assertIn('undo acl ipv6 name test-filter', output)
        print(acl)

    @capture.stdout
    def testMixed(self):
        acl = self._Render(GOOD_HEADER_MIXED, GOOD_TERM_SIMPLE)
        output = str(acl)
        self.assertIn('acl name test-filter advance', output)
        self.assertIn('acl ipv6 name ipv6-test-filter advance', output)
        print(acl)

    @capture.stdout
    def testVerbatim(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_VERBATIM)
        output = str(acl)
        self.assertIn('rule 5 permit ip source any destination any', output)
        print(acl)

    @capture.stdout
    def testIcmpType(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_ICMP)
        output = str(acl)
        self.assertIn('icmp', output)
        print(acl)

    @capture.stdout
    def testHeaderComment(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_COMMENT)
        output = str(acl)
        self.assertIn('remark this is a test acl', output)
        print(acl)

    @capture.stdout
    def testAclHeaderFormat(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SIMPLE)
        output = str(acl)
        self.assertIn('undo acl name test-filter', output)
        self.assertIn('acl name test-filter advance', output)
        print(acl)

    @capture.stdout
    def testSectionTerminator(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SIMPLE)
        output = str(acl)
        self.assertTrue(output.rstrip().endswith('#'))
        print(acl)

    def testNoTermRemark(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SIMPLE)
        self.assertNotIn('remark good-term', str(acl))

    def testBuildTokens(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SIMPLE)
        st, sst = acl._BuildTokens()
        self.assertEqual(st, SUPPORTED_TOKENS)
        self.assertEqual(sst, SUPPORTED_SUB_TOKENS)

    def testRepositoryTagsUseHash(self):
        acl = self._Render(GOOD_HEADER, GOOD_TERM_SIMPLE)
        output = str(acl)
        # Huawei uses # for comments, not !
        self.assertIn('# $Id:$', output)
        self.assertNotIn('! $Id:$', output)

    def testDuplicateTermError(self):
        duplicate_terms = GOOD_TERM_SIMPLE + GOOD_TERM_SIMPLE
        with self.assertRaises(huawei_vrp8.HuaweiVRP8DuplicateTermError):
            self._Render(GOOD_HEADER, duplicate_terms)

    def testUnsupportedFilterTypeError(self):
        bad_header = """
header {
  target:: huawei-vrp8 test-filter object-group
}
"""
        with self.assertRaises(huawei_vrp8.UnsupportedHuaweiVRP8FilterError):
            self._Render(bad_header, GOOD_TERM_SIMPLE)


if __name__ == '__main__':
    absltest.main()
