import json
from base64 import decodebytes, encodebytes
from datetime import datetime
from typing import AnyStr, ByteString, Dict, List

import requests
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from requests.utils import quote


__all__ = ['AliPay']


class AliPay:
    def __init__(self, pay_config: Dict):
        self.appid = pay_config.get('ALIPAY_APP_ID')
        self.notify_url = pay_config.get('ALIPAY_NOTIFY_URL')
        self.return_url = pay_config.get('ALIPAY_RETURN_URL')
        self.sign_type = pay_config.get('ALIPAY_SIGN_TYPE')
        if pay_config.get('ALIPAY_DEBUG', False):
            self.gateway = pay_config.get('ALIPAY_DEBUG_GATEWAY')
        else:
            self.gateway = pay_config.get('ALIPAY_GATEWAY')
        self.alipay_public_key = pay_config.get('ALIPAY_PUBLIC_KEY')
        self.app_private_key = pay_config.get('ALIPAY_APP_PRIVATE_KEY')
        self.app_public_key = pay_config.get('ALIPAY_APP_PUBLIC_KEY')

    def api_alipay_trade_page_pay(self, biz_content: Dict = None) -> AnyStr:
        """
        网页支付接口
        :param biz_content: 扩展支付内容
        """

        data = self._build_body("alipay.trade.page.pay", biz_content)
        request_url_suffix = self._sign_data(data)  # 生成携带签名的后缀
        request_url = '?'.join([self.gateway, request_url_suffix])
        return request_url

    def api_alipay_trade_query(self,
                               out_trade_no: AnyStr = None,
                               trade_no: AnyStr = None) -> Dict:
        """
         网页支付查询接口
        :param out_trade_no:  自建订单号
        :param trade_no: 支付宝返回订单号
        """

        result = {}
        biz_content = {}
        if out_trade_no:
            biz_content["out_trade_no"] = out_trade_no
        if trade_no:
            biz_content["trade_no"] = trade_no
        data = self._build_body("alipay.trade.query", biz_content)
        url = self.gateway + "?" + self._sign_data(data)
        try:
            response = requests.request('GET', url, timeout=3)
        except Exception:
            response = {}
        if not response:
            return result
        raw_string = response.content.decode("utf-8")
        return_trade_status = self._verify_sync_response(
            raw_string, "alipay_trade_query_response"
        )
        if return_trade_status:
            response = json.loads(raw_string)
            result = response.get('alipay_trade_query_response')
        return result

    def verify(self, data: Dict) -> bool:
        """
        外部公钥验证
        :param data: 回调接口返回数据
        """

        signature = data.pop("sign", None)
        sign_type = data.pop("sign_type", None)
        if sign_type != self.sign_type or data.get('auth_app_id') != self.appid:
            return False
        if data.get('trade_status') not in ["TRADE_SUCCESS", "TRADE_FINISHED"]:
            return False
        unsigned_items = self._ordered_data(data)  # 排序验签
        raw_content = "&".join("{}={}".format(k, v) for k, v in unsigned_items)
        return self._verify(raw_content, signature)

    def _build_body(self, method: AnyStr, biz_content: Dict) -> Dict:
        """
         构建满足阿里FORMAT(只支持json)
        :param method: 支付方式：网页支付，
        :param biz_content: 阿里FORMAT
        """

        data = {
            "app_id": self.appid,
            "biz_content": biz_content,
            "charset": "utf-8",
            "method": method,
            "notify_url": self.notify_url,
            "return_url": self.return_url,
            "sign_type": self.sign_type,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": "1.0",
        }
        return data

    def _sign_data(self, data: Dict) -> AnyStr:
        """ 返回签名后缀 """

        unsigned_list = []
        quoted_list = []
        data.pop("sign", None)
        # 排序后的字符串
        ordered_items = self._ordered_data(data)
        # 组建签名后缀
        for key, value in ordered_items:
            unsigned_list.append("{}={}".format(key, value))
            quoted_list.append("{}={}".format(key, quote(value)))
        unsigned_string = "&".join(unsigned_list)
        quoted_string = "&".join(quoted_list)
        sign = self._sign(unsigned_string)
        # 字符串str类型转为url编码
        signed_string = quoted_string + "&sign=" + quote(sign)
        return signed_string

    def _sign(self, unsigned_string: AnyStr):
        """ 签名计算 """

        key = self.load_key(self.app_private_key)
        signer = PKCS1_v1_5.new(key)
        signature = signer.sign(SHA256.new(unsigned_string.encode('utf-8')))
        sign = encodebytes(signature).decode("utf-8").replace("\n", "")
        return sign

    def _verify_sync_response(self, raw_string, response_type) -> bool:
        """
        如果验证成功返回True, 否则返回False或者None
        :param raw_string:  支付宝返回内容
        :param response_type: 支付方式
        """

        try:
            response = json.loads(raw_string)
        except Exception:
            response = {}
        sign = response.get('sign')
        result = response.get(response_type)
        if not sign:
            return False
        if result.get('trade_status') not in ["TRADE_SUCCESS", "TRADE_FINISHED"]:
            return False
        raw_string = self._get_string_to_be_signed(raw_string, response_type)
        verify_status = self._verify(raw_string, sign)
        return verify_status

    def _verify(self, raw_content: AnyStr, signature: AnyStr) -> bool:
        """ 内部公钥验证 """

        if not raw_content or not signature:
            return False
        if isinstance(raw_content, str):
            raw_content: ByteString = raw_content.encode("utf8")
        if isinstance(signature, str):
            signature: ByteString = signature.encode("utf8")
        key = self.load_key(self.alipay_public_key)
        signer = PKCS1_v1_5.new(key)
        digest = SHA256.new(raw_content)
        return bool(signer.verify(digest, decodebytes(signature)))

    @staticmethod
    def _ordered_data(data) -> List:
        sort_data = []
        for key in sorted(data.keys()):
            value = data.get(key, None)
            if isinstance(value, bytes):
                sort_data.append((key, value.decode('utf-8')))
            elif isinstance(value, dict):
                value = json.dumps(value, separators=(',', ':'))
                sort_data.append((key, value))
            elif value:
                sort_data.append((key, value))
            else:
                continue
        return sort_data

    @staticmethod
    def load_key(key_path: AnyStr):
        with open(key_path, 'r') as key:
            _key = RSA.importKey(key.read())
        return _key

    @staticmethod
    def _get_string_to_be_signed(raw_string, response_type) -> AnyStr:
        """
        https://doc.open.alipay.com/docs/doc.htm?docType=1&articleId=106120
        从同步返回的接口里面找到待签名的字符串
        必须按照支付宝返回的顺序来验签名，python json dumps无法做到保持顺序
        """

        balance = 0
        start = end = raw_string.find("{", raw_string.find(response_type))
        # 从response_type之后的第一个｛的下一位开始匹配，
        # 如果是｛则balance加1; 如果是｝而且balance=0，就是待验签字符串的终点
        for _index, _char in enumerate(raw_string[start + 1:], start + 1):
            if _char == "{":
                balance += 1
            elif _char == "}":
                if balance == 0:
                    end = _index + 1
                    break
                balance -= 1
        return raw_string[start:end]
