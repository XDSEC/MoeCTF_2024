from PIL import Image, ImageDraw, ImageFont
from os import getenv
# 打开已有的图像
image_path = './flag.jpg'
image = Image.open(image_path)

# 创建一个绘图对象
draw = ImageDraw.Draw(image)

# 定义要绘制的文本
text = "moectf{CeleBr4Te_You_AtT4ck-to_My-1LliI_CLO0uD1c1e}"

# 选择字体和大小
font_path = "./arial.ttf"  # Update path as necessary
font = ImageFont.truetype(font_path,35)



# 计算文本大小
bbox = draw.textbbox((0, 0), text, font=font)
text_width = bbox[2] - bbox[0]
text_height = bbox[3] - bbox[1]

# 计算文本位置（居中）
image_width, image_height = image.size
x = (image_width - text_width) / 2  # 中心对齐
y = (image_height - text_height) / 2  # 中心对齐

# 绘制文本
draw.text((x, y), text, font=font, fill='red')  # 红色字体

# 保存修改后的图像
image.save('./flag.jpg')


def append_text_to_jpeg(image_path, output_path, text):
    # 将字符串转换为二进制数据
    binary_text = text.encode('utf-8')

    # 读取JPEG文件的二进制数据
    with open(image_path, 'rb') as file:
        image_data = file.read()

    # 找到FFD9 (JPEG结束标记)的位置
    ffd9_position = image_data.rfind(b'\xFF\xD9')
    if ffd9_position == -1:
        raise ValueError("未找到JPEG结束标记 FFD9")

    # 在FFD9之后插入字符串的二进制数据
    modified_image_data = image_data[:ffd9_position+2] + binary_text + image_data[ffd9_position+2:]

    # 将修改后的二进制数据写入到新的JPEG文件
    with open(output_path, 'wb') as file:
        file.write(modified_image_data)

    print(f"字符串已成功写入到 {output_path} 文件的 FFD9 之后")

# 使用该函数
image_path = './flag.jpg'
output_path = './uploads/flag.jpg'

append_text_to_jpeg(image_path, output_path, text)


