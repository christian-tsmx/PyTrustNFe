# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import re
import os
import sys
from decimal import Decimal
import requests
from lxml import etree
from requests import Session
from pytrustnfe.nfse.nfpaulistana.assinatura import Assinatura
from pytrustnfe.xml import render_xml, sanitize_response
from pytrustnfe.certificado import extract_cert_and_key_from_pfx, save_cert_key


def _render(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), "templates")
    parser = etree.XMLParser(
        remove_blank_text=True, remove_comments=True, strip_cdata=False
    )
    signer = Assinatura(certificado.pfx, certificado.password)

    referencia = ""
    if method == "EnvioRPS":
        #Processar campos dos RPS
        for i, rps in enumerate(kwargs["nfse"]["lista_rps"]):            
            #==========
            #Tributação
            #==========
            tributacao = None
            #M – Micro Empreendedor Individual (MEI)
            if str(rps["regime_tributacao"]) == "5":
                tributacao = "M"
            #C - Isenta de ISS
            elif str(rps["natureza_operacao"]) == '3':
                tributacao = "C"
            #F - Imune
            elif str(rps["natureza_operacao"]) == '4':
                tributacao = "F"
            #K – Exigibilidade Sus.Dec. J/Proc.A
            elif str(rps["natureza_operacao"]) in ['5','6']:
                tributacao = "K"
            #H - Tributável - Simples Nacional
            elif str(rps["optante_simples"]) == "1":
                tributacao = "H"
            #E - Não Incidência no Município
            elif str(rps["natureza_operacao"]) in ['1','2'] and str(rps["servico"]["codigo_municipio"]) != str(rps["tomador"]["codigo_municipio"]):
                tributacao = "E"
            #N - Não tributável
            elif str(rps["natureza_operacao"]) in ['1','2'] and str(rps["servico"]["iss"]) == "0.00":
                tributacao = "N"
            #T - Tributável
            else:
                tributacao = "T"
            
            kwargs["nfse"]["lista_rps"][i]["tributacao"] = tributacao
        signer.gerar_assinatura_rps(**kwargs)

    xml_string_send = render_xml(path, "%s.xml" % method, True, **kwargs)

    # xml object
    xml_send = etree.fromstring(
        xml_string_send, parser=parser)

    if method == "recepcionarLoteRps":
        xml_signed_send = signer.assina_xml(
            xml_send, "lote:{0}".format(referencia))
    elif method == "cancelarNfse":
        xml_signed_send = signer.assina_xml(
            xml_send, kwargs["nfse"]["rps"]["numero"])
    else:
        xml_signed_send = etree.tostring(xml_send)

    print ('--- xml ---')
    print (xml_signed_send)

    return xml_signed_send

def _send(certificado, method, **kwargs):
    path = os.path.join(os.path.dirname(__file__), "templates")

    url = "%s/%s.%sHttpSoap11Endpoint" %(kwargs["base_url"], method2function[method], method2function[method])
    print(url)

    xml_send = kwargs["xml"]
    path = os.path.join(os.path.dirname(__file__), "templates")
    soap = render_xml(path, "SoapRequest.xml", True, **{"soap_body":xml_send, "method": method })

    cert, key = extract_cert_and_key_from_pfx(certificado.pfx, certificado.password)
    cert, key = save_cert_key(cert, key)
    session = Session()
    session.cert = (cert, key)
    session.verify = False
    action = "urn:%s" %(method)
    headers = {
        "Content-Type": "text/xml;charset=UTF-8",
        "SOAPAction": action,
        "Operation": method,
        "Content-length": str(len(soap))
    }

    request = requests.post(url, data=soap, headers=headers)
    response, obj = sanitize_response(request.content.decode('utf8', 'ignore'))
    try:
        return {"sent_xml": str(soap), "received_xml": str(response.encode('utf8')), "object": obj.Body }
    except:
        return {"sent_xml": str(soap), "received_xml": str(response), "object": obj.Body }

def xml_recepcionar_lote_rps(certificado, **kwargs):
    return _render(certificado, "EnvioRPS", **kwargs)

def recepcionar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_recepcionar_lote_rps(certificado, **kwargs)
    return _send(certificado, "EnvioRPS", **kwargs)

def xml_cancelar_nfse(certificado, **kwargs):
    return _render(certificado, "cancelarNfse", **kwargs)

def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_cancelar_nfse(certificado, **kwargs)
    response = _send(certificado, "cancelarNfse", **kwargs)
    xml = None

    try:
        #Conversão a objeto e Busca pelo elemento Nfse
        res, xml_obj = sanitize_response(response['object']['cancelarNfseResponse']['return'].text)
        #Caso haja algum erro, as mensagens serão retornadas
        if xml_obj.find(".//ListaMensagemRetorno") is not None:
            xml_obj = xml_obj.find(".//ListaMensagemRetorno")
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

def xml_consultar_lote_rps(certificado, **kwargs):
    return _render(certificado, "consultarLoteRps", **kwargs)

def consultar_lote_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consultar_lote_rps(certificado, **kwargs)
    response = _send(certificado, "consultarLoteRps", **kwargs)
    xml = None

    try:
        xml_clean = re.sub(r'\<\?xml.+\?\>\n?','',response['object']['consultarLoteRpsResponse']['return'].text)
        res, xml_obj = sanitize_response(xml_clean)
        xml = etree.tostring(xml_obj,xml_declaration=False)
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

def xml_consultar_nfse_por_rps(certificado, **kwargs):
    return _render(certificado, "consultarNfsePorRps", **kwargs)

def consultar_nfse_por_rps(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_consultar_nfse_por_rps(certificado, **kwargs)
    response = _send(certificado, "consultarNfsePorRps", **kwargs)
    xml = None

    try:
        res, xml_obj = sanitize_response(response['object']['consultarNfsePorRpsResponse']['return'].text)
        xml_obj = xml_obj.find(".//CompNfse")
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