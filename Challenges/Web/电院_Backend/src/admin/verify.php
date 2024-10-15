<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

header('Content-type: image/png');

// 生成验证码文本
$code = substr(md5(uniqid()), 0, 4); // 生成 4 位的验证码
$_SESSION['captcha_code'] = $code;

// 创建图像
$width = 100;
$height = 40;
$image = imagecreatetruecolor($width, $height);

// 设置颜色
$bgColor = imagecolorallocate($image, 255, 255, 255); // 背景色：白色
$textColor = imagecolorallocate($image, 0, 0, 0);      // 文字色：黑色

// 填充背景色
imagefilledrectangle($image, 0, 0, $width, $height, $bgColor);

// 添加干扰线条
$lineColor = imagecolorallocate($image, 64, 64, 64);   // 线条色：灰色
for ($i = 0; $i < 5; $i++) {
    imageline($image, rand(0, $width), rand(0, $height), rand(0, $width), rand(0, $height), $lineColor);
}

// 添加验证码文本
$fontSize = 5; // 使用内置字体
$textX = ($width - imagefontwidth($fontSize) * strlen($code)) / 2;
$textY = ($height - imagefontheight($fontSize)) / 2;
imagestring($image, $fontSize, $textX, $textY, $code, $textColor);

// 输出图像
imagepng($image);
imagedestroy($image);
?>
