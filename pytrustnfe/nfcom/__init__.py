# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).


import os
import requests
from lxml import etree
from pytrustnfe.nfcom.assinatura import Assinatura
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.utils import  gerar_chave_nfcom,nfcom_qrcode,ChaveNFCom
from pytrustnfe.Servidores import localizar_url
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Zeep
from requests import Session
from zeep import Client
from zeep.transports import Transport
import logging.config
import base64
import zlib
import struct
import time
import gzip
try:
    from StringIO import StringIO
except ImportError:
    # original line
    #from io import StringIO

    # fix
    import io as StringIO



def _generate_nfcom_id(**kwargs):
    item = kwargs.get("infNFCom")
    vals = {
        "cnpj": item["emit"]["cnpj_cpf"],
        "estado": item["ide"]["cUF"],
        "emissao": "%s%s"
        % (
            item["ide"]["dhEmi"][2:4],
            item["ide"]["dhEmi"][5:7],
        ),
        "modelo": item["ide"]["mod"],
        "serie": item["ide"]["serie"],
        "numero": item["ide"]["nNF"],
        "tipo": item["ide"]["tpEmis"],
        "codigo": item["ide"]["cNF"],
        "site_aut": 0,
    }
    chave_nfcom = ChaveNFCom(**vals)
    chave_nfcom = gerar_chave_nfcom(chave_nfcom)
    item["Id"] = chave_nfcom[:len(chave_nfcom)]
    item["ide"]["cDV"] = chave_nfcom[len(chave_nfcom) - 1 :]
    item["qrCodNFCom"] = nfcom_qrcode(chave_nfcom[5:len(chave_nfcom)],kwargs["ambiente"],item["ide"]["cUF"])


def _render(certificado, method, sign, **kwargs):
    path = os.path.join(os.path.dirname(__file__), "templates")
    xmlElem_send = render_xml(path, "%s.xml" % method, True, **kwargs["infNFCom"])
    xml_obj = etree.fromstring(xmlElem_send)

    if sign:
        signer = Assinatura(certificado.pfx, certificado.password)
        if method == "NFComRecepcao":
            xml_send = signer.assina_xml(xml_obj, kwargs["infNFCom"]["Id"])

    else:
        xml_send = xmlElem_send
    return xml_send


def _get_session(certificado):
    cert, key = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)

    session = Session()
    session.headers['Accept-Encoding'] = "gzip,deflate"
    session.headers['Content-Type'] = "application/soap+xml"
    session.cert = (cert, key)
    session.verify = False
    return session


def _get_client(base_url, transport):
    client = Client(base_url, transport=transport)
    port = next(iter(client.wsdl.port_types))
    first_operation = [
        x
        for x in iter(client.wsdl.port_types[port].operations)
        if "zip" not in x.lower()
    ][0]
    return first_operation, client


def _send(certificado, method, **kwargs):
    xml_send = kwargs["xml"]
    base_url = localizar_url(
        method, kwargs["estado"], kwargs["modelo"], kwargs["ambiente"]
    )
    logging.config.dictConfig({
        'version': 1,
        'formatters': {
            'verbose': {
                'format': '%(name)s: %(message)s'
            }
        },
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'verbose',
            },
        },
        'loggers': {
            'zeep.transports': {
                'level': 'DEBUG',
                'propagate': True,
                'handlers': ['console'],
            },
        }
    })
    session = _get_session(certificado)
    transport = Transport(session=session,timeout=300)
    print(base_url)
    first_op, client = _get_client(base_url, transport)
    return _send_zeep(first_op, client, xml_send, method == "NFComRecepcao")


def _send_zeep(first_operation, client, xml_send_raw, b64_encode = False):
    #Base64 encode
    print(xml_send_raw)
    xml_send = ""
    if b64_encode:
        ###
        #gzip_header = struct.pack("<BBBBLBB", 0x1f, 0x8b, 8, 0, int(time.time()), 2, 255)
        #gzip_trailer = struct.pack("<LL", zlib.crc32(xml_send_raw), (len(xml_send_raw) & 0xffffffff))
        #compress_obj = zlib.compressobj(9, zlib.DEFLATED, -15)
        #xml_bytes = compress_obj.compress(xml_send_raw.encode())
        #xml_bytes = compress_obj.flush()
        #b64_bytes = base64.b64encode(gzip_header + xml_bytes + gzip_trailer)
        #xml_send  = b64_bytes.decode('utf-8')
        ###
        out_file = StringIO()
        gzip_file = gzip.GzipFile(fileobj=out_file, mode='wb')
        gzip_file.write(xml_send_raw.encode('utf-8'))
        gzip_file.close()
        b64_bytes = base64.b64encode(out_file.getvalue())
        xml_send = b64_bytes.decode('utf-8')
    else:
        xml_send  = xml_send_raw

    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    with client.settings(raw_response=True):
        response = client.service[first_operation](xml_send)
        response, obj = sanitize_response(response.text)
        return {
            "sent_xml": xml_send,
            "received_xml": response,
            "object": obj.Body.getchildren()[0],
        }


def xml_autorizar_nfcom(certificado, **kwargs):
    _generate_nfcom_id(**kwargs)
    return _render(certificado, "NFComRecepcao", True, **kwargs)


def autorizar_nfcom(certificado, **kwargs):  # Assinar
    if "xml" not in kwargs:
        kwargs["xml"] = xml_autorizar_nfcom(certificado, **kwargs)
    return _send(certificado, "NFComRecepcao", **kwargs)