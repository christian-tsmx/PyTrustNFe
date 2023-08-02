# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

from OpenSSL import crypto
import signxml
from lxml import etree
from signxml import XMLSigner,XMLVerifier
import sys

class Assinatura(object):

    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    def extract_cert_key(self):
        pfx = crypto.load_pkcs12(self.cert, self.key)
        key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pfx.get_privatekey())
        cert = crypto.dump_certificate(crypto.FILETYPE_PEM, pfx.get_certificate())

        return cert, key
    
    def assina_nfts_xml(self, xml_element):
        cert, key = self.extract_cert_key()

        signer = XMLSigner(method=signxml.methods.enveloped, 
                           signature_algorithm="rsa-sha1",
                           digest_algorithm='sha1',
                           c14n_algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')

        signer.namespaces = {None: signxml.namespaces.ds}

        for nfts in xml_element.findall(".//{https://nfse.salvador.ba.gov.br/nfts}NFTS"):
            signed_root = signer.sign(nfts, key=key.encode(), cert=cert.encode())

            signature_value = signed_root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text
            signature_elem = etree.Element("Assinatura")
            signature_elem.text = signature_value
            
            nfts.append(signature_elem)

        if sys.version_info[0] > 2:
            return etree.tostring(xml_element, encoding=str)
        else:
            return etree.tostring(xml_element, encoding="utf8")

    def assina_xml(self, xml):
        cert, key = self.extract_cert_key()

        signer = XMLSigner(method=signxml.methods.enveloped, 
                           signature_algorithm="rsa-sha1",
                           digest_algorithm='sha1',
                           c14n_algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')

        ns = {None: signer.namespaces['ds']}
        signer.namespaces = ns

        signed_root = signer.sign(xml, key=key, cert=cert)

        encoding = "utf8"        
        if sys.version_info[0] > 2:
            encoding = str
            
        xml_output = etree.tostring(signed_root, encoding=encoding)

        return xml_output