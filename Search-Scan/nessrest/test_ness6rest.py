# Copyright (c) 2014-2015, Tenable Network Security, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#   - Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.
#   - Redistributions in binary form must reproduce the above copyright notice,
#     this list of conditions and the following disclaimer in the documentation
#     and/or other materials provided with the distribution.
#   - Neither the name of Tenable Network Security, Inc. nor the names of its
#     contributors may be used to endorse or promote products derived from this
#     software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, TITLE,
# NON-INFRINGEMENT, INTEGRATION, PERFORMANCE, AND ACCURACY AND ANY IMPLIED
# WARRANTIES ARISING FROM STATUTE, COURSE OF DEALING, COURSE OF PERFORMANCE, OR
# USAGE OF TRADE, ARE DISCLAIMED. IN NO EVENT SHALL TENABLE NETWORK SECURITY,
# INC., OR ANY SUCCESSOR-IN-INTEREST, BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import os
import ness6rest as nessrest
import credentials

def test_deduplicate_hosts():
    login = os.getenv("NESSUS_USER")
    password = os.getenv("NESSUS_PASSWORD")
    url = "https://%s:%s" % (os.getenv("NESSUS_SERVER"),
                             os.getenv("NESSUS_PORT", "8834"))

    scan = nessrest.Scanner(url=url, login=login, password=password)

    hosts = [{'hostname': 'host1', 'host_id': '1'},
             {'hostname': 'host1', 'host_id': '1'},
             {'hostname': 'host2', 'host_id': '2'}]
    unique_hosts = scan._deduplicate_hosts(hosts=hosts)
    assert unique_hosts  == \
        [{'hostname': 'host2', 'host_id': '2'},
         {'hostname': 'host1', 'host_id': '1'}]

    assert scan._deduplicate_hosts(hosts=[]) == []

def test_SSH_Cisco_escalation():
    cred = credentials.SshPassword(username="admin", password="pass") \
        .cisco_enable("pass2")

    assert cred.__dict__ == {'auth_method': 'password',
                             'elevate_privileges_with': "Cisco 'enable'",
                             'escalation_password': 'pass2',
                             'password': 'pass',
                             'username': 'admin'}

    assert cred.category == "Host"
    assert cred.name == "SSH"

def test_SSH_sudo_escalation_default_account():
    cred = credentials.SshPassword(username="admin", password="pass") \
        .sudo("pass2")

    assert cred.__dict__ == {'auth_method': 'password',
                             'elevate_privileges_with': 'sudo',
                             'escalation_password': 'pass2',
                             'escalation_account': 'root',
                             'password': 'pass',
                             'username': 'admin'}

    assert cred.category == "Host"
    assert cred.name == "SSH"

def test_SSH_sudo_escalation():
    cred = credentials.SshPassword(username="admin", password="pass") \
        .sudo(username="nessus", password="pass2")

    assert cred.__dict__ == {'auth_method': 'password',
                             'elevate_privileges_with': 'sudo',
                             'escalation_password': 'pass2',
                             'escalation_account': 'nessus',
                             'password': 'pass',
                             'username': 'admin'}

    assert cred.category == "Host"
    assert cred.name == "SSH"

def test_SSH_password():
    cred = credentials.SshPassword(username="admin",
                           password="pass")

    assert cred.__dict__ == {'auth_method': 'password',
                             'elevate_privileges_with': 'Nothing',
                             'username': 'admin',
                             'password': 'pass'}

    assert cred.category == "Host"
    assert cred.name == "SSH"

def test_SSH_public_key():
    cred = credentials.SshPublicKey(username="admin",
                                 private_key_filename="test.cer",
                                 private_key_passphrase="passphrase")

    assert cred.__dict__ == {'auth_method': 'public key',
                             'elevate_privileges_with': 'Nothing',
                             'username': 'admin',
                             'private_key': 'test.cer',
                             'private_key_passphrase': 'passphrase'}

    assert cred.category == "Host"
    assert cred.name == "SSH"
