# -*- coding: utf-8 -*-
# © 2019 Danimar Ribeiro, Trustcode
# License AGPL-3.0 or later (http://www.gnu.org/licenses/agpl.html).

import os
import json
import requests
from decimal import Decimal


def _parse(certificado, method, **kwargs):
    obj_lista = []
    
    if method == "RecepcionarLoteRps":
        lote = kwargs.get("nfse")
        for nfse in lote["lista_rps"]:
            prestador = nfse.get('prestador', {})
            servico = nfse.get('servico', {})
            tomador = nfse.get('tomador', {})
            
            obj = {
                'data_emissao': str(nfse.get('data_emissao', '')),
                'numero_rps': str(nfse.get('numero','')),
                'serie': str(nfse.get('serie','')),
                'natureza_operacao': str(nfse.get('natureza_operacao', '')),
                'regime_especial_tributacao': str(nfse.get('regime_tributacao', '')),
                'optante_simples_nacional': bool(nfse.get('optante_simples', False)),
                'incentivador_cultural': bool(str(nfse.get('incentivador_cultural', '2')) == '1'),
                'prestador': {
                    'cnpj': str(prestador.get('cnpj', '')),
                    'codigo_municipio': str(servico.get('codigo_municipio', '')),
                    'inscricao_municipal': str(prestador.get('inscricao_municipal', '')),
                },
                'tomador': {
                    'cpf': str(tomador.get('cpf_cnpj','')) if len(str(tomador.get('cpf_cnpj',''))) == 11 else '',
                    'cnpj': str(tomador.get('cpf_cnpj','')) if len(str(tomador.get('cpf_cnpj',''))) == 14 else '',
                    'inscricao_municipal': str(tomador.get('inscricao_municipal', '')),
                    'razao_social': str(tomador.get('razao_social', '')),
                    'telefone': str(tomador.get('telefone', '')),
                    'email': str(tomador.get('email','')),
                    'endereco': {
                        'logradouro': str(tomador.get('endereco','')),
                        'tipo_logradouro': str(tomador.get('tipo_endereco', '')),
                        'numero': str(tomador.get('numero', 'SN')),
                        'complemento': str(tomador.get('complemento','')),
                        'bairro': str(tomador.get('bairro','')),
                        'codigo_municipio': str(tomador.get('codigo_municipio','')),
                        'uf': str(tomador.get('uf','')),
                        'cep': str(tomador.get('cep','')),
                    },
                },
                'servico': {
                    'valor_servicos': Decimal(servico.get('valor_servico', 0.0)),
                    'valor_deducoes': Decimal(servico.get('valor_deducoes', 0.0)),
                    'valor_pis': Decimal(servico.get('valor_pis', 0.0)),
                    'valor_cofins': Decimal(servico.get('valor_cofins', 0.0)),
                    'valor_inss': Decimal(servico.get('valor_inss', 0.0)),
                    'valor_ir': Decimal(servico.get('valor_ir', 0.0)),
                    'valor_csll': Decimal(servico.get('valor_csll', 0.0)),
                    'iss_retido': bool(str(servico.get('iss_retido', '2')) == '1'),
                    'valor_iss': Decimal(servico.get('iss', 0.0)),
                    'base_calculo': Decimal(servico.get('base_calculo', 0.0)),
                    'aliquota': Decimal(servico.get('aliquota', 0.0)) * Decimal(100.0),
                    'item_lista_servico': str(servico.get('codigo_atividade','')),
                    'codigo_cnae': str(servico.get('cnae_servico','')),
                    'discriminacao': str(servico.get('discriminacao','')),
                    'codigo_municipio': str(servico.get('codigo_municipio','')),
                },
            }
            obj_lista.append(obj)
    return obj_lista

def _send(certificado, method, **kwargs):
    base_url = ""
    
    if kwargs["ambiente"] == "homologacao":
        base_url = "https://homologacao.focusnfe.com.br/v2/nfse"
    else:
        base_url = "https://api.focusnfe.com.br/v2/nfse"

    headers = {
        "Content-Type": "application/json",
    }
    ref = {
        'ref': 'L%sR%sS%s' %(str(kwargs.get('numero_lote')).zfill(2),
                             str(kwargs.get('numero_rps')).zfill(2),
                             str(kwargs.get('serie')).zfill(2),
                             )
    }

    status, r = requests.post(base_url, params=ref, headers=headers, data=json.dumps(kwargs.get('data')), auth=(kwargs.get('token'), ''))

    return {"sent_xml": json.dumps(kwargs.get('data')), "received_xml": '[STATUS %d]: %s' %(status,str(r.text)), "object": r.json() }

def xml_recepcionar_lote_rps(certificado, **kwargs):
    return _parse(certificado, "RecepcionarLoteRps", **kwargs)

def recepcionar_lote_rps(certificado, **kwargs):
    ret = []
    data = xml_recepcionar_lote_rps(certificado, **kwargs)
    nfse = kwargs.pop('nfse')
    kwargs["token"] = nfse.get('chave_digital')
    kwargs["numero_lote"] = nfse.get('numero_lote')
    for nf_send in data:
        kwargs["data"] = nf_send
        kwargs["numero_rps"] = kwargs["data"].pop('numero_rps')
        kwargs["serie"] = kwargs["data"].pop('serie')
        ret.append(_send(certificado, "RecepcionarLoteRps", **kwargs))
    return "\n\n".join(ret)

def consultar_nfse_por_rps(certificado, **kwargs):
    return _send(certificado, "ConsultarNfsePorRps", **kwargs)

def xml_cancelar_nfse(certificado, **kwargs):
    return _parse(certificado, "CancelarNfse", **kwargs)

def cancelar_nfse(certificado, **kwargs):
    if "xml" not in kwargs:
        kwargs["xml"] = xml_cancelar_nfse(certificado, **kwargs)
    return _send(certificado, "CancelarNfse", **kwargs)
