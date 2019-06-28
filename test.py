from flask import Flask, current_app
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

app = Flask(__name__)


pay_config = {}


@app.route('/')
def test():
    from pay_libs.alipay import AliPay
    from pay_libs.wxpay import WxPay
    return 'ok'


if __name__ == '__main__':
    app.run(debug=True)
