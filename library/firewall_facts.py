#!/usr/bin/python
# coding: utf-8 -*-

# (c) 2018, Michael Scherer <mscherer@redhat.com>
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
author:
- Michael Scherer (@mscherer)
module: firewall_facts
short_description: Gather facts about firewall
description:
- Gather facts about firewall
version_added: "2.X"
options: []
'''

EXAMPLES = '''
'''

from ansible.module_utils.basic import AnsibleModule, get_platform
import os


def detect_service(module, service):
    systemctl = module.get_bin_path("systemctl")
    rc, o, e = module.run_command("%s is-active %s" % (systemctl, service))
    if rc == 0:
        return True
    rc, o, e = module.run_command("%s is-enabled %s" % (systemctl, service))
    return rc == 0


def detect_rcconf(module, service):
    for l in open('/etc/rc.conf').readlines():
        if l.startswith('%s="YES"' % service):
            return True
    return False


def detect_linux_fw(module):
    for i in ("firewalld", "nftables", "iptables", "shorewall"):
        if detect_service(module, i):
            return i
    # native firewall
    return "iptables"


def detect_freebsd_fw(module):
    for i in ['pf', 'ipfilter']:
        if detect_rcconf(module, '%s_enable' % i):
            return i
    if detect_rcconf(module, 'firewall_enable'):
        return 'ipfw'
    # https://www.freebsd.org/doc/handbook/firewalls-pf.html
    # arbitrary default, since that's the native one
    return "ipfw"


def detect_openbsd_fw(module):
    return "pf"


def detect_netbsd_fw(module):
    for i in ['pf', 'npf']:
        if os.stat('/dev/%s' % i):
            return i
    if detect_rcconf(module, 'ipfilter'):
        return 'ipfilter'
    return 'pf'

FW_VTABLE = {
    'Linux': detect_linux_fw,
    'FreeBSD': detect_freebsd_fw,
    'NetBSD': detect_netbsd_fw,
    'OpenBSD': detect_openbsd_fw
}


def main():
    module = AnsibleModule(
        argument_spec=dict(),
    )
    p = get_platform()
    if p in FW_VTABLE:
        f = FW_VTABLE[p](module)
        module.exit_json(
            changed=False,
            ansible_facts={'firewall': f}
        )
    else:
        module.fail_json()

if __name__ == '__main__':
    main()
