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

"""Huawei VRP8 (CE16800) ACL generator.

This module generates ACL configuration for Huawei CloudEngine switches
running VRP8, such as the CE16800.

ACL syntax reference:
  IPv4 advanced ACL:
    acl name <name> advance
     rule <id> {permit|deny} <proto> source <src> <wildcard> destination <dst> <wildcard>
    #
  IPv6 advanced ACL:
    acl ipv6 name <name> advance
     rule <id> {permit|deny} <proto> source <ipv6-prefix> <prefixlen> destination ...
    #
"""

import ipaddress

from aerleon.lib import aclgenerator, cisco, nacaddr
from aerleon.lib.policy import Policy

_COMMENT_MAX_WIDTH = 70


class Error(aclgenerator.Error):
    """Generic error class."""


class HuaweiVRP8DuplicateTermError(Error):
    """Raised on duplicate term names."""


class UnsupportedHuaweiVRP8FilterError(Error):
    """Raised when an unsupported filter type is used."""


class Term(cisco.Term):
    """A single Huawei VRP8 ACL rule."""

    def _GetIpString(self, addr) -> str:
        """Format an address for a Huawei VRP8 ACL rule.

        Huawei IPv6 subnets use space-separated prefix length
        (e.g. '2001:db8:: 32') rather than CIDR slash notation.
        The prefixlen != 0 guard ensures '::/0' is still handled by the
        parent as 'any', not reformatted to ':: 0'.
        """
        if (
            isinstance(addr, (nacaddr.IPv6, ipaddress.IPv6Network))
            and addr.prefixlen != 0
            and addr.num_addresses > 1
        ):
            return f'{addr.network_address} {addr.prefixlen}'
        return super()._GetIpString(addr)

    def _FixConsecutivePorts(self, port_list):
        """Huawei VRP8 does not require consecutive-port expansion."""
        return port_list

    def _TermletToStr(
        self,
        action,
        proto,
        saddr,
        sport,
        daddr,
        dport,
        icmp_type,
        icmp_code,
        option,
    ) -> list[str]:
        """Build a single Huawei VRP8 rule line (without the rule-id prefix).

        The caller is responsible for prepending 'rule <seq>' when assembling
        the final output.
        """
        icmp_type = str(icmp_type)
        icmp_code = str(icmp_code)

        parts = [action, str(proto), f'source {saddr}']

        if sport:
            parts.append(f'source-port {sport}')

        parts.append(f'destination {daddr}')

        if dport:
            parts.append(f'destination-port {dport}')

        if icmp_type:
            parts.append(f'icmp-type {icmp_type}')
        if icmp_code:
            parts.append(f'icmp-code {icmp_code}')

        for opt in option:
            if opt == 'log':
                parts.append('logging')
            elif opt == 'fragments':
                parts.append('fragment')
            else:
                parts.append(opt)

        return [f" {' '.join(parts)}"]


class HuaweiVRP8(cisco.Cisco):
    """A Huawei VRP8 (CE16800) ACL policy object."""

    _PLATFORM = 'huawei-vrp8'
    SUFFIX = '.hvrp'
    _PROTO_INT = False
    _TERM_REMARK = False

    def _BuildTokens(self) -> tuple[set[str], dict[str, set[str]]]:
        """Build supported tokens for Huawei VRP8.

        Cisco-specific tokens 'address' and 'dscp_match' are not supported.
        """
        supported_tokens, supported_sub_tokens = super()._BuildTokens()
        supported_tokens -= {'address', 'dscp_match'}
        return supported_tokens, supported_sub_tokens

    def _TranslatePolicy(self, pol: Policy, exp_info: int) -> None:
        """Translate policy to Huawei VRP8 internal representation."""
        self.cisco_policies = []
        good_filters = ['extended', 'inet6', 'mixed']

        for header, terms in pol.filters:
            filter_options = header.FilterOptions(self._PLATFORM)
            filter_name = header.FilterName(self._PLATFORM)

            self.verbose = True
            if 'noverbose' in filter_options:
                filter_options.remove('noverbose')
                self.verbose = False

            filter_type = 'extended'
            if len(filter_options) > 1:
                filter_type = filter_options[1]

            if filter_type not in good_filters:
                raise UnsupportedHuaweiVRP8FilterError(
                    f'ACL filter type {filter_type!r} is not supported by'
                    f' {self._PLATFORM} (supported: {good_filters})'
                )

            filter_list = [filter_type]
            if filter_type == 'mixed':
                filter_list = ['extended', 'inet6']

            for next_filter in filter_list:
                af_int = 4 if next_filter == 'extended' else 6
                af_str = 'inet' if af_int == 4 else 'inet6'

                term_dup_check = set()
                new_terms = []
                for term in terms:
                    if term.name in term_dup_check:
                        raise HuaweiVRP8DuplicateTermError(
                            f'Duplicate term name: {term.name}'
                        )
                    term_dup_check.add(term.name)

                    term.name = self.FixTermLength(term.name)
                    term = self.FixHighPorts(term, af=af_str)
                    if not term:
                        continue

                    if (
                        term.restrict_address_family
                        and term.restrict_address_family != af_str
                    ):
                        continue

                    new_terms.append(
                        Term(
                            term,
                            af=af_int,
                            proto_int=self._PROTO_INT,
                            enable_dsmo=False,
                            term_remark=self._TERM_REMARK,
                            platform=self._PLATFORM,
                            verbose=self.verbose,
                            filter_type=filter_type,
                        )
                    )

                current_filter_name = filter_name
                if filter_type == 'mixed' and next_filter == 'inet6':
                    current_filter_name = f'ipv6-{filter_name}'

                self.cisco_policies.append(
                    (header, current_filter_name, [next_filter], new_terms, None)
                )

    def _AppendTargetByFilterType(self, filter_name: str, filter_type: str) -> list[str]:
        """Return Huawei VRP8 ACL header lines for the given filter type."""
        target = []
        if filter_type == 'inet6':
            target.append(f'undo acl ipv6 name {filter_name}')
            target.append(f'acl ipv6 name {filter_name} advance')
        else:
            target.append(f'undo acl name {filter_name}')
            target.append(f'acl name {filter_name} advance')
        return target

    def __str__(self) -> str:
        target = []
        target.extend(aclgenerator.AddRepositoryTags('# '))

        for header, filter_name, filter_list, terms, _ in self.cisco_policies:
            for filter_type in filter_list:
                target.extend(self._AppendTargetByFilterType(filter_name, filter_type))

                if self.verbose:
                    target.extend(
                        aclgenerator.AddRepositoryTags(' remark ', date=False, revision=False)
                    )
                    for comment in aclgenerator.WrapWords(header.comment, _COMMENT_MAX_WIDTH):
                        for line in comment.split('\n'):
                            target.append(f' remark {line}')

                seq = 5
                for term in terms:
                    term_str = str(term)
                    if not term_str:
                        continue
                    for line in term_str.split('\n'):
                        stripped = line.strip()
                        if not stripped:
                            continue
                        if stripped.startswith('remark'):
                            target.append(f' {stripped}')
                        elif stripped.startswith('permit') or stripped.startswith('deny'):
                            target.append(f' rule {seq} {stripped}')
                            seq += 5
                        elif stripped.startswith('rule '):
                            # Verbatim rule line — passed through as-is.
                            # Note: verbatim rules carry their own rule ID so the
                            # auto-sequence counter is NOT advanced here.  Callers
                            # using verbatim are responsible for avoiding ID conflicts
                            # with auto-generated rules.
                            target.append(f' {stripped}')

                target.append('#')

        return '\n'.join(target)
