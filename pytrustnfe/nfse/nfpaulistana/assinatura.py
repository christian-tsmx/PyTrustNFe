# -*- coding: utf-8 -*-
# © 2016 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import sys
import re
import hashlib
from collections import OrderedDict
from OpenSSL import crypto
import signxml
from lxml import etree
from signxml import XMLSigner

class Assinatura(object):

    def __init__(self, cert, key):
        self.cert = cert
        self.key = key

    def gerar_assinatura_rps(self, **kwargs):
        for i, rps in enumerate(kwargs['nfse']['lista_rps']):
            chave_raw = ""
            campos = (
                #Composição: (name, max_length, rjust or ljust, padding_data)
                ('im', 8, 'rjust', '0'),                #01 - Inscrição do contribuinte
                ('serie_rps', 5, 'ljust', ' '),         #02 - Série do RPS
                ('numero_rps', 12, 'rjust', '0'),       #03 - Número do RPS
                ('dt_emissao', 8, 'ljust', ' '),        #04 - Data Emissão - yyyyMMdd
                ('trib', 1, 'ljust', ' '),              #05 - Tributação
                ('status', 1, 'rjust', '0'),            #06 - Status do RPS
                ('iss_retido', 1, 'rjust', '0'),        #07 - Tipo Recolhimento (S ou N)
                ('valor_servico', 15, 'rjust', '0'),    #08 - Valor do Serviço subtraido de deduções
                ('valor_deducoes', 15, 'rjust', '0'),   #09 - Valor da dedução
                ('cod_atividade', 5, 'rjust', '0'),     #10 - Código do Serviço Prestado
                ('tomador_ind', 1, 'rjust', '0'),       #11 - Indicador de CPF/CNPJ Tomador (1 CPF 2 CNPJ 3 Não Informado)
                ('cpfcnpj_tomador', 14, 'rjust', '0'),  #12 - CPF/CNPJ do Tomador
                ('intermed_ind', 1, 'rjust', '0'),      #13 - Indicador de CPF/CNPJ Intermediário (1 CPF 2 CNPJ 3 Não Informado)
                ('cpfcnpj_intermed', 14, 'rjust', '0'), #14 - CPF/CNPJ do Intermediário
                ('iss_ret_intermed', 1, 'rjust', '0'),  #15 - ISS Retido Intermediário (S ou N)
            )

            kwargs['nfse']['lista_rps'][i]['status'] = "N" if rps['status'] == "1" else "C"
            kwargs['nfse']['lista_rps'][i]['servico']['iss_retido'] = "S" if rps['servico']['iss_retido'] == "1" else "N"

            dados = OrderedDict()
            dados['im'] = rps['prestador']['inscricao_municipal']
            dados['serie_rps'] = "NF"
            dados['numero_rps'] = rps['numero']
            dados['dt_emissao'] = rps['data_emissao'].split("T")[0].replace("-","")
            dados['trib'] = rps['tributacao']
            dados['status'] = kwargs['nfse']['lista_rps'][i]['status']
            dados['iss_retido'] = "S" if str(kwargs['nfse']['lista_rps'][i]['servico']['iss_retido']) == "1" else "N"
            dados['valor_servico'] = rps['servico']['valor_servico']
            dados['valor_deducoes'] = rps['servico']['deducoes']
            dados['cod_atividade'] = rps['servico']['codigo_atividade']
            if rps['tomador']['cpf_cnpj']:
                dados['tomador_ind'] = '1' if len(str(rps['tomador']['cpf_cnpj'])) == 11 else '2'
            else:
                dados['tomador_ind'] = '3'
            dados['cpfcnpj_tomador'] = rps['tomador']['cpf_cnpj']
            if rps['intermed']['cpf_cnpj']:
                dados['intermed_ind'] = '1' if len(str(rps['intermed']['cpf_cnpj'])) == 11 else '2'
            else:
                dados['intermed_ind'] = '3'
            dados['cpfcnpj_intermed'] = rps['intermed']['cpf_cnpj']

            #Gerar chave na ordem dos campos informada
            for campo in campos:
                chave_raw += getattr(re.sub(r'[^a-zA-Z0-9 ]', '', str(dados[campo[0]])[:campo[1]].strip()), campo[2])(campo[1],campo[3])
            
            #não é necessário informar os dados de intermediário na assinatura se não houver intermediário
            if dados['intermed_ind'] == '3':
                chave_raw = chave_raw[:-16]
            
            kwargs['nfse']['lista_rps'][i]['assinatura'] = hashlib.sha1(chave_raw).hexdigest()

    def extract_cert_key(self):
        pfx = crypto.load_pkcs12(self.cert, self.key)
        key = crypto.dump_privatekey(crypto.FILETYPE_PEM, pfx.get_privatekey())
        cert = crypto.dump_certificate(crypto.FILETYPE_PEM, pfx.get_certificate())

        return cert, key

    def assina_xml(self, xml_element, reference, getchildren=False, **kwargs):
        cert, key = self.extract_cert_key()

        signer = XMLSigner(method=signxml.methods.enveloped, 
                           signature_algorithm="rsa-sha1",
                           digest_algorithm='sha1',
                           c14n_algorithm='http://www.w3.org/TR/2001/REC-xml-c14n-20010315')

        ns = {}
        ns[None] = signer.namespaces['ds']
        signer.namespaces = ns

        ref_uri = ('#%s' % reference) if reference else None

        element = xml_element.find(".//*[@id='%s']" % (reference))
        if element is None:
            element = xml_element.find(".//*[@Id='%s']" % (reference))
        signed_root = signer.sign(
            element, key=key.encode(), cert=cert.encode(),
            reference_uri=ref_uri)

        if reference:
            element_signed = xml_element.find(".//*[@id='%s']" % (reference))
            if element_signed is None:
                element_signed = xml_element.find(".//*[@Id='%s']" % (reference))
            signature = signed_root.findall(".//{http://www.w3.org/2000/09/xmldsig#}Signature")[-1]

            if kwargs.get('include_ref'):
                signature.set(kwargs['include_ref'], reference)

            if element_signed is not None and signature is not None:
                parent = element_signed.getparent()
                parent.append(signature)

            if kwargs.get('remove_attrib'):
                element_signed.attrib.pop(kwargs['remove_attrib'], None)

        if sys.version_info[0] > 2:
            return etree.tostring(xml_element, encoding=str)
        else:
            return etree.tostring(xml_element, encoding="utf8")