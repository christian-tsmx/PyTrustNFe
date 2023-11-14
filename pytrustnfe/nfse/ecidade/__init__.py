# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import os
from lxml import etree
from pytrustnfe.xml import render_xml, sanitize_response
import requests 

cancelamento_error = {
    8:'MÊS COMPETÊNCIA',
    9:'LOCAL DA PRESTAÇÃO',
    10:'ALÍQUOTA',
    11:'BASE DE CALCULO',
    12:'DESCRIÇÃO DOS SERVIÇOS',
    13:'DIVERGÊNCIA CADASTRAL',
    14:'DADOS DO TOMADOR',
}

def _render_xml(certificado, method, **kwargs):
    kwargs['method'] = method
    path = os.path.join(os.path.dirname(__file__), "templates")
    parser = etree.XMLParser(
        remove_blank_text=True, remove_comments=True, strip_cdata=False
    )

    xml_string_send = render_xml(path, "%s.xml" % method, True, **kwargs)    
    return xml_string_send

def _send(certificado, method, **kwargs):
    base_url = kwargs["base_url"] + "/" + method.lower()

    if kwargs["ambiente"] == "homologacao":
        base_url = base_url + "/simula"

    xml_send = kwargs["xml"]
    headers = {
        "Content-Type": "application/xml;charset=UTF-8",
        "Content-length": str(len(xml_send)),
        "Cache-Control": "no-cache",
        "Authorization": kwargs["nfse"]["inscricao_municipal"] + "-" + kwargs["nfse"]["chave_digital"],
    }

    request = requests.post(base_url, data=xml_send, headers=headers)
    response, obj = sanitize_response(request.content.decode('utf8', 'ignore'))
    return {"sent_xml": str(xml_send), "received_xml": str(response.encode('utf8')), "object": obj }

def xml_recepcionar_lote_rps(certificado, **kwargs):
    return _render_xml(certificado, "Emissao", **kwargs)

def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_recepcionar_lote_rps(certificado, **kwargs)
    return _send(certificado,"Emissao", **kwargs)

def xml_cancelar_nfse(certificado, **kwargs):
    return _render_xml(certificado, "Cancela", **kwargs)

def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_cancelar_nfse(certificado, **kwargs)
    response = _send(certificado, "Cancela", **kwargs)
    res = sanitize_response(response['received_xml'])
    if "nfeResposta" in response['received_xml']:
        return etree.tostring(res[1])
    return None

def xml_consultar_nfse_por_rps(certificado, **kwargs):
    return _render_xml(certificado, "Consulta", **kwargs)

def consultar_nfse_por_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consultar_nfse_por_rps(certificado, **kwargs)
    response = _send(certificado, "Consulta", **kwargs)
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