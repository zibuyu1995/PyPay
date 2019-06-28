import hashlib
import hmac
import logging
import uuid
from typing import Dict, AnyStr, List, Tuple

import requests
from lxml import etree
from requests import Response
from requests.exceptions import Timeout


logger = logging.getLogger(__name__)


class WxPay:
    def __init__(self, pay_config: Dict):
        self.appid = pay_config.get('WX_APP_ID')
        self.mch_id = pay_config.get('WX_MCH_ID')
        self.mch_key = pay_config['WX_MCH_KEY']
        self.notify_url = pay_config['WX_NOTIFY_URL']
        self.sign_type = pay_config.get('WX_SIGN_TYPE')
        self.trade_type = pay_config.get('WX_TRADE_TYPE')
        if pay_config.get('WXPAY_DEBUG', False):
            self.gateway = pay_config['WX_GATEWAY']
        else:
            self.gateway = pay_config['WX_DEBUG_GATEWAY']

    def unified_order(self, biz_content: Dict) -> AnyStr:
        """ 统一下单接口 """

        extend_body = {
            'product_id': self._random_uid(),  # 32 bit product id
            'notify_url': self.notify_url,
            'trade_type': 'NATIVE'  # Native pay
        }
        order_data = self._build_body(extend_body)
        order_data.update(biz_content)  # 更新自定义订单内容
        order_data['sign'] = self._sign(order_data)
        xml_data = self.dict_to_xml(order_data)
        unified_order_url = f"{self.gateway}/unifiedorder"
        response = self._request('POST', unified_order_url, data=xml_data)
        response_dict = self._handle_response(response)
        code_url = response_dict.get('code_url')
        return code_url

    def order_query(self,
                    out_trade_no: AnyStr,
                    transaction_id: AnyStr = None) -> Dict:
        """ 订单查询 """

        order_data = self._build_body()
        order_data['out_trade_no'] = out_trade_no  # 订单号
        if transaction_id:
            order_data['transaction_id'] = transaction_id  # 微信交易号
        order_data['sign'] = self._sign(order_data)
        query_order_url = f"{self.gateway}/orderquery"
        xml_data = self.dict_to_xml(order_data)
        response = self._request('POST', url=query_order_url, data=xml_data)
        response_dict = self._handle_response(response)
        return response_dict

    def get_sandbox_key(self):
        """ 获取沙箱秘钥 """

        get_sandbox_url = 'https://api.mch.weixin.qq.com/sandboxnew/pay/getsignkey'
        data = {
            'mch_id': self.mch_id,
            'nonce_str': self._random_uid(),
        }
        data['sign'] = self._sign(data)
        xml_data = self.dict_to_xml(data)
        response = self._request('POST', url=get_sandbox_url, data=xml_data)
        response_dict = self._handle_response(response)
        sign_key = response_dict.get('sandbox_signkey')
        return sign_key

    def verify(self, data: Dict) -> bool:
        """ 公钥验证 """

        signature = data.pop('sign', None)
        if not data or not signature:
            return False
        return signature == self._sign(data)

    def _build_body(self, extend_body: Dict = None) -> Dict:
        """ 构建微信支付基础请求参数 """

        data = {
            'appid': self.appid,  # app id
            'mch_id': self.mch_id,  # 商户id
            'nonce_str': self._random_uid(),  # 随机32字符串
            'trade_type': self.trade_type,  # 交易类型
            'sign_type': self.sign_type,  # HMAC-SHA256
        }
        if extend_body:
            data.update(extend_body)
        return data

    def _sign(self, data: Dict) -> AnyStr:
        """
        HMAC-SHA256 签名
        HMAC-SHA256签名方式:hmac.new(key, msg, method) key:双方签名秘钥，msg: 签名消息
        """

        data.pop('key', None)
        ordered_items = self._ordered_data(data)
        prefix_sign = "&".join("{}={}".format(k, v) for k, v in ordered_items)  # 组建签名前缀
        signed_string = f"{prefix_sign}&key={self.mch_key}"  # 组建签名后缀
        signed = hmac.new(
            key=self.mch_key.encode('utf-8'),
            msg=signed_string.encode('utf-8'),
            digestmod=hashlib.sha256
        ).hexdigest().upper()  # 加密后字符串转换为大写
        return signed

    def _handle_response(self, response: Response) -> Dict:
        """ 微信支付 response 处理 """

        response_dict = {}
        if response.status_code != 200 or not response.content:
            return response_dict
        response_dict = self.xml_to_dict(response.content)
        return_code = response_dict.get('return_code')
        return_msg = response_dict.get('return_msg')
        if return_code != 'SUCCESS' or return_msg != 'OK':
            logger.debug(f"{return_code}: {return_msg}")
            return {}
        return response_dict

    @staticmethod
    def _random_uid():
        return str(uuid.uuid1()).replace('-', '')

    @staticmethod
    def _ordered_data(data: Dict) -> List[Tuple]:
        """ 字典按照 ASCII 码从小到大排序后转换为列表 """

        sort_data = []
        for key in sorted(data.keys()):
            value = data.get(key, None)
            if isinstance(value, bytes):
                sort_data.append((key, value.decode('utf-8')))
            elif value:
                sort_data.append((key, value))
            else:
                continue
        return sort_data

    @staticmethod
    def dict_to_xml(data: Dict) -> AnyStr:
        row_xml_list = []
        for key, value in data.items():
            if not value:
                break
            if isinstance(value, bytes):
                value = value.decode('utf-8')
            row_xml_list.append(f"<{key}>{value}</{key}>")
        xml_string = ''.join(row_xml_list)
        return f"<xml>{xml_string}</xml>"

    @staticmethod
    def xml_to_dict(content: AnyStr) -> Dict:
        if isinstance(content, str):
            content = content.encode('utf-8')
        content_dict = {}
        try:
            root = etree.fromstring(
                content,
                parser=etree.XMLParser(resolve_entities=False)
            )
        except Exception as e:
            logger.debug(e)
            root = []
        for child in root:
            content_dict[child.tag] = child.text
        return content_dict

    @staticmethod
    def _request(method, url, data=None) -> Response:
        if isinstance(data, str):
            data = data.encode('utf-8')
        try:
            response = requests.request(method, url, data=data, timeout=3)
            logger.debug(f"{method}-{url}: {response}")
        except Timeout:
            logger.error(f"{method}-{url}: timeout")
            response = Response()
            response.status_code = 500
        except ConnectionError:
            logger.error(f"{method}-{url}: ConnectionError")
            response = Response()
            response.status_code = 500
        except Exception as e:
            logger.error(f"{method}-{url}: {e}")
            response = Response()
            response.status_code = 500
        return response
