import os
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# SQLite 数据库文件路径
DATABASE = os.getenv('DATABASE', 'example.db')

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # 使查询结果以字典形式返回
    return conn

@app.route('/', methods=['GET'])
def index():
    return app.send_static_file('index.html')

@app.route('/confession_count', methods=['GET'])
def get_confession_count():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM confessions")
    count = cursor.fetchone()[0]
    conn.close()
    if count >= 300:
        return jsonify({'count': count, 'flag': 'moectf{testflag}','Qixi_flag': 'moeCTF{Happy_Chin3s3_Va13ntin3\'s_Day,_Baby.}'})
    else:
        return jsonify({'count': count, 'flag': 'Your love is not yet fulfilled','Qixi_flag': 'Your love is not yet fulfilled'})

@app.route('/questionnaire', methods=['OPTIONS'])
def options_request():
    response = app.make_response('')
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'POST, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type'
    return response

@app.route('/questionnaire', methods=['POST'])
def submit_questionnaire():
    conn = get_db_connection()
    cursor = conn.cursor()
    data = request.get_json()
    required_fields = ['nickname', 'target', 'message', 'user_gender', 'target_gender', 'anonymous']
    for field in required_fields:
        if field not in data:
            return jsonify({'success': False})
    cursor.execute(
        "INSERT INTO confessions (nickname, target, message, user_gender, target_gender, anonymous) VALUES (?, ?, ?, ?, ?, ?)",
        (data['nickname'], data['target'], data['message'], data['user_gender'], data['target_gender'], data['anonymous'])
    )
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)