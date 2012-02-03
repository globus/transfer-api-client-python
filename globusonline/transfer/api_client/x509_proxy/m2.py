# Copyright 2012 University of Chicago
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Implementation using M2Crypto.
"""
import struct
import os
import time

from M2Crypto import X509, RSA, EVP, ASN1, BIO


def get_random_serial():
    """
    Under RFC 3820 there are many ways to generate the serial number. However
    making the number unpredictable has security benefits, e.g. it can make
    this style of attack more difficult:

    http://www.win.tue.nl/hashclash/rogue-ca
    """
    return struct.unpack("<Q", os.urandom(8))[0]


def create_proxy_from_file(issuer_cred_file, public_key, lifetime_hours=1):
    """
    Create a proxy of the credential in issuer_cred_file, using the
    specified public key and lifetime.

    @param issuer_cred_file: file containing a credential, including the
                             certificate, public key, and optionally chain
                             certs.
    @param public_key: the public key as a PEM string
    @param lifetime_hours: lifetime of the proxy in hours (default 1)
    """
    with open(issuer_cred_file) as f:
        issuer_cred = f.read()
    return create_proxy(issuer_cred, public_key, lifetime_hours)


_begin_private_key = "-----BEGIN RSA PRIVATE KEY-----"
_end_private_key = "-----END RSA PRIVATE KEY-----"

# The issuer is required to have this bit set if keyUsage is present;
# see RFC 3820 section 3.1.
REQUIRED_KEY_USAGE = ["Digital Signature"]
def create_proxy(issuer_cred, public_key, lifetime_hours):
    old_proxy = False

    # Standard order is cert, private key, then the chain.
    _begin_idx = issuer_cred.index(_begin_private_key)
    _end_idx = issuer_cred.index(_end_private_key) + len(_end_private_key)
    issuer_key = issuer_cred[_begin_idx:_end_idx]
    issuer_cert = issuer_cred[:_begin_idx]
    issuer_chain = issuer_cert + issuer_cred[_end_idx:]

    proxy = X509.X509()
    proxy.set_version(2)
    serial = get_random_serial()
    proxy.set_serial_number(serial)

    now = long(time.time())
    not_before = ASN1.ASN1_UTCTIME()
    not_before.set_time(now)
    proxy.set_not_before(not_before)

    not_after = ASN1.ASN1_UTCTIME()
    not_after.set_time(now + lifetime_hours * 3600)
    proxy.set_not_after(not_after)

    pkey = EVP.PKey()
    tmp_bio = BIO.MemoryBuffer(str(public_key))
    rsa = RSA.load_pub_key_bio(tmp_bio)
    pkey.assign_rsa(rsa)
    del rsa
    del tmp_bio
    proxy.set_pubkey(pkey)

    issuer = X509.load_cert_string(issuer_cert)

    # Examine the last CN to see if it looks like and old proxy.
    cn_entries = issuer.get_subject().get_entries_by_nid(
                                        X509.X509_Name.nid["CN"])
    if cn_entries:
        last_cn = cn_entries[-1].get_data()
        old_proxy = (str(last_cn) in ("proxy", "limited proxy"))

    # If the issuer has keyUsage extension, make sure it contains all
    # the values we require.
    try:
        keyUsageExt = issuer.get_ext("keyUsage")
        if keyUsageExt:
            values = keyUsageExt.get_value().split(", ")
            for required in REQUIRED_KEY_USAGE:
                if required not in values:
                    raise InterfaceError(
                      "issuer contains keyUsage without required usage '%s'"
                      % required)
    except LookupError:
        keyUsageExt = None

    # hack to get a copy of the X509 name that we can append to.
    issuer_copy = X509.load_cert_string(issuer_cert)
    proxy_subject = issuer_copy.get_subject()
    if old_proxy:
        proxy_subject.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC,
                                       entry="proxy",
                                       len=-1, loc=-1, set=0)
    else:
        proxy_subject.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC,
                                       entry=str(serial),
                                       len=-1, loc=-1, set=0)
    proxy.set_subject(proxy_subject)
    proxy.set_issuer(issuer.get_subject())

    # create a full proxy (legacy/old or rfc, draft is not supported)
    if old_proxy:
        # For old proxies, there is no spec that defines the interpretation,
        # so the keyUsage extension is more important.
        # TODO: copy extended key usage also?
        if keyUsageExt:
            # Copy from the issuer if it had a keyUsage extension.
            ku_ext = X509.new_extension("keyUsage", keyUsageExt.get_value(), 1)
        else:
            # Otherwise default to this set of usages.
            ku_ext = X509.new_extension("keyUsage",
                "Digital Signature, Key Encipherment, Data Encipherment", 1)
        proxy.add_ext(ku_ext)
    else:
        # For RFC proxies the effictive usage is defined as the intersection
        # of the usage of each cert in the chain. See section 4.2 of RFC 3820.
        # We opt not to add keyUsage.
        pci_ext = X509.new_extension("proxyCertInfo",
                                     "critical,language:Inherit all", 1)
        proxy.add_ext(pci_ext)

    issuer_rsa = RSA.load_key_string(issuer_key)
    sign_pkey = EVP.PKey()
    sign_pkey.assign_rsa(issuer_rsa)
    proxy.sign(pkey=sign_pkey, md="sha1")
    return proxy.as_pem() + issuer_chain
