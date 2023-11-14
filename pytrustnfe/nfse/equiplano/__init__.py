# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import os
import sys
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key
from lxml import etree
from zeep.transports import Transport
from requests import Session
import requests
from datetime import datetime, timedelta
from pytrustnfe.nfse.siasp.assinatura import Assinatura


def _render(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), "templates")
    parser = etree.XMLParser(
        remove_blank_text=True, remove_comments=True, strip_cdata=False
    )
    signer = Assinatura(certificado.pfx, certificado.password)

    xml_string_send = render_xml(path, "%s.xml" % method, True, False, **kwargs)

    # xml object
    xml_send = etree.fromstring(
        xml_string_send, parser=parser)
    
    xml_signed_send = signer.assina_xml(xml_send)

    return xml_signed_send

def _send(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), "templates")

    if kwargs["ambiente"] == "homologacao":
        url = "https://www.esnfs.com.br:9444/homologacaows/services/Enfs?wsdl"
    else:
        url = "https://www.esnfs.com.br:8444/enfsws/services/Enfs?wsdl"

    xml_send = kwargs["xml"]
    path = os.path.join(os.path.dirname(__file__), "templates")
    soap = render_xml(path, "SoapRequest.xml", False, False, **{"soap_body":xml_send, "method": method })

    cert, key = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)
    session = Session()
    session.cert = (cert, key)
    session.verify = False
    headers = {
        "Content-Type": "application/soap+xml;charset=UTF-8",
        "Operation": "es" + method,
        "Content-length": str(len(soap))
    }

    request = requests.post(url, data=soap, headers=headers,verify=False,cert=(cert, key))
    response, obj = sanitize_response(request.content.decode('utf8', 'ignore'))
    return {"sent_xml": str(soap), "received_xml": str(response.encode('utf8')), "object": obj.Body }

def xml_recepcionar_lote_rps(certificado, **kwargs):
    return _render(certificado, "RecepcionarLoteRps", **kwargs)

def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_recepcionar_lote_rps(certificado, **kwargs)
    return _send(certificado, "RecepcionarLoteRps", **kwargs)

def gerar_nfse(certificado, **kwargs):
    return _send(certificado, "GerarNfse", **kwargs)


def envio_lote_rps_assincrono(certificado, **kwargs):
    return _send(certificado, "RecepcionarLoteRps", **kwargs)

def envio_lote_rps(certificado, **kwargs):
    return _send(certificado, "RecepcionarLoteRpsSincrono", **kwargs)

def xml_cancelar_nfse(certificado, **kwargs):
    return _render(certificado, "CancelarNfse", **kwargs)

def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_cancelar_nfse(certificado, **kwargs)
    response = _send(certificado, "CancelarNfse", **kwargs)
    xml = None

    try:
        #Conversão a objeto e Busca pelo elemento Nfse
        res, xml_obj = sanitize_response(response['object']['esCancelarNfseResponse']['return'].text)
        #Caso haja algum erro, as mensagens serão retornadas
        if xml_obj.find(".//listaErros") is not None:
            xml_obj = xml_obj.find(".//listaErros")
        else:
            xml_obj = xml_obj.find('')
        #Conversão de volta a string
        xml = etree.tostring(xml_obj)
        if sys.version_info[0] > 2:
            from html.parser import HTMLParser
            xml = xml.encode(str)
        else:
            from HTMLParser import HTMLParser
            xml = xml.encode('utf-8','ignore')
        #unescape
        xml = HTMLParser().unescape(xml)
    except Exception as err:
        pass

    return xml


def substituir_nfse(certificado, **kwargs):
    return _send(certificado, "SubstituirNfse", **kwargs)


def consulta_situacao_lote_rps(certificado, **kwargs):
    return _send(certificado, "ConsultaSituacaoLoteRPS", **kwargs)


def xml_consultar_nfse_por_rps(certificado, **kwargs):
    return _render(certificado, "ConsultarNfsePorRps", **kwargs)

def consultar_nfse_por_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consultar_nfse_por_rps(certificado, **kwargs)
    response = _send(certificado, "ConsultarNfsePorRps", **kwargs)
    xml = None

    try:
        res, xml_obj = sanitize_response(response['object']['esConsultarNfsePorRpsResponse']['return'].text)
        xml_obj = xml_obj.find(".//nfse")
        #Conversão de volta a string
        xml = etree.tostring(xml_obj)
        if sys.version_info[0] > 2:
            from html.parser import HTMLParser
            xml = xml.encode(str)
        else:
            from HTMLParser import HTMLParser
            xml = xml.encode('utf-8','ignore')
        #unescape
        xml = HTMLParser().unescape(xml)
    except:
        pass

    return xml


def consultar_lote_rps(certificado, **kwargs):
    return _send(certificado, "ConsultarLoteRps", **kwargs)


def consulta_nfse_servico_prestado(certificado, **kwargs):
    return _send(certificado, "ConsultarNfseServicoPrestado", **kwargs)


def consultar_nfse_servico_tomado(certificado, **kwargs):
    return _send(certificado, "ConsultarNfseServicoTomado", **kwargs)


def consulta_nfse_faixe(certificado, **kwargs):
    return _send(certificado, "ConsultarNfseFaixa", **kwargs)


def consulta_cnpj(certificado, **kwargs):
    return _send(certificado, "ConsultaCNPJ", **kwargs)