from errno import ELIBSCN
from operator import ne
import random
import os
import time

from flask import Flask, render_template, request, session

app = Flask(__name__)
app.secret_key = os.urandom(24)

# 赋值 flag
flag_env = os.getenv('FLAG')
if flag_env is not None:
    flag = flag_env
else:
    flag = "moectf{fake_flag}"

direct_list = ["北方", "东北方", "东方", "东南方", "南方", "西南方", "西方", "西北方"]

def gen_direct():
    # 设置铜钱数量
    coin_count = random.choice([1, 2])
    coin = []
    coin.append(random.choice(range(1, 9)))
    if coin_count == 2:
        # 如果抽到一样的,那就算同一个
        next = random.choice(range(1, 9))
        if next != coin[0]:
            coin.append(next)
        else:
            coin_count = 1
    return coin_count, coin

def check_direct(resp):
    pass
    # 一个硬币
    if session['coin_count'] == 1 and resp == direct_list[session['coin'][0] - 1]:
        return True
    elif session['coin_count'] == 2 and resp == str(direct_list[session['coin'][0] - 1] + "一个，" + direct_list[session['coin'][1] - 1] + "一个"):
        return True
    else:
        return False


@app.route("/restart", methods=["GET"])
def restart():
    session.clear()
    return render_template("index.html", status="已重新开始")


@app.route("/", methods=["GET", "POST"])
def index():
    # return render_template("index.html", status="<span style=\"color:blue;\">hhh</span>")
    if request.method == "GET":
        return render_template("index.html")
    elif request.method == "POST":
        # 新选手
        if request.form.get('player') != session.get('player') :
            if request.form.get('direct') == '弟子明白':
                session['player'] = request.form.get('player')
                session['round'] = 0
                # session['start_time'] = time.time()
                session['time'] = time.time()
                session['coin_count'], session['coin'] = gen_direct()
                return render_template("index.html", status=(str(session['coin'])[1:-1]))
            else:
                return render_template("index.html", status="<span style=\"color:red;\">你是上来捣乱的吗?</span>")
        # 老选手
        elif request.form.get('player') == session.get('player'):
            if request.form.get('direct') == '弟子明白':
                return render_template("index.html", status="<span style=\"color:red;\">你又明白了?</span>")
            # 已经阵亡了
            elif session['round'] == -1:
                return render_template("index.html", status="<span style=\"color:red;\">你已经倒地了</span>")
            # 回答正确
            elif check_direct(request.form.get('direct')):
                # 时间到了,该罚!
                if time.time() - session['time'] > 3:
                    session['round'] = -1
                    return render_template("index.html", status="<span style=\"color:red;\">太慢了，该罚！（应声倒地）</span>")
                elif session['round'] == 4:
                    return render_template("index.html", status="<span style=\"color:green;\">你过关！（过关的小曲）<br>" + flag + "</span>")
                elif 0 <= session['round'] <= 3:
                    session['round'] += 1
                    # 重置时间
                    session['time'] = time.time()
                    session['coin_count'], session['coin'] = gen_direct()
                    return render_template("index.html", status=(str(session['coin'])[1:-1]))


            else:
                session['round'] = -1
                return render_template("index.html", status="<span style=\"color:red;\">该罚！(应声倒地)</span>")




if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=80)