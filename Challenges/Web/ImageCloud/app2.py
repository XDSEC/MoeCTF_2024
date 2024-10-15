from flask import Flask, request, send_file, abort, redirect, url_for
import os
import requests
from io import BytesIO
from PIL import Image
import mimetypes
from werkzeug.utils import secure_filename
import socket
import random


app = Flask(__name__)

# 设置上传文件夹
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# 支持的图片格式
ALLOWED_EXTENSIONS = {'jpg', 'jpeg', 'png', 'gif'}

# 存储上传的文件名
uploaded_files = []

def find_free_port_in_range(start_port, end_port):
    while True:
        port = random.randint(start_port, end_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', port))
        s.close()
        return port  # 找到可用端口



def allowed_file(filename):
    """检查文件是否为允许的格式"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_mimetype(file_path):
    """获取文件的 MIME 类型"""
    mime = mimetypes.guess_type(file_path)[0]
    if mime is None:
        # 使用 PIL 库检测文件 MIME 类型
        try:
            with Image.open(file_path) as img:
                mime = img.get_format_mimetype()
        except Exception:
            mime = 'application/octet-stream'
    return mime

@app.route('/')
def index():
    return '''
    <h1>图片上传</h1>
    <form method="post" enctype="multipart/form-data" action="/upload">
      <input type="file" name="file">
      <input type="submit" value="上传">
    </form>
    <h2>已上传的图片</h2>
    <ul>
    ''' + ''.join(f'<li><a href="/image/{filename}">{filename}</a></li>' for filename in uploaded_files) + '''
    </ul>
    '''

# 上传图片的API
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return '未找到文件部分', 400
    file = request.files['file']

    if file.filename == '':
        return '未选择文件', 400
    if file and allowed_file(file.filename):
        # 确保文件名是安全的
        filename = secure_filename(file.filename)
        ext = filename.rsplit('.', 1)[1].lower()

        # 使用独特的文件名来防止覆盖
        unique_filename = f"{len(uploaded_files)}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)

        # 保存文件到上传文件夹
        file.save(filepath)
        uploaded_files.append(unique_filename)

        return redirect(url_for('index'))
    else:
        return '文件类型不支持', 400

# 图片加载的API
@app.route('/image/<filename>', methods=['GET'])
def load_image(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(filepath):
        mime = get_mimetype(filepath)
        return send_file(filepath, mimetype=mime)
    else:
        return '文件未找到', 404

if __name__ == '__main__':
    if not os.path.exists(UPLOAD_FOLDER):
        os.makedirs(UPLOAD_FOLDER)
    port = find_free_port_in_range(5001, 6000)
    print(f"Running on port {port}")
    app.run(host='0.0.0.0', port=port)
