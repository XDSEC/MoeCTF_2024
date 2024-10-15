<?php
// 确保脚本通过POST方法接收数据
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // 设置上传目录
    $uploadDir = "uploads/";
    // 确保上传目录存在
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0777, true);
    }

    // 检查是否有文件被上传
    if (!empty($_FILES['image']['name'])) {
        // 获取文件信息
        $fileName = basename($_FILES['image']['name']);
        $fileTmpName = $_FILES['image']['tmp_name'];
        $fileSize = $_FILES['image']['size'];
        $fileType = $_FILES['image']['type'];

//         文件验证（这里只作为示例，你可能需要更复杂的验证）
        $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        if (!in_array($fileType, $allowedTypes)) {
            die('文件类型好像不对哦');
        }

        // 文件大小限制（示例：最大2MB）
        $maxSize = 2 * 1024 * 1024;
        if ($fileSize > $maxSize) {
            die('Error: File size is too large.');
        }

        // 构建完整文件路径
        $filePath = $uploadDir . $fileName;

        // 尝试移动文件到指定目录
        if (move_uploaded_file($fileTmpName, $filePath)) {
            echo "文件上传成功！你的图片将被存储在：" . $filePath;
        } else {
            echo "Error: There was a problem uploading the file.";
        }
    } else {
        echo "Error: No file was uploaded.";
    }
} else {
    echo "Error: Invalid request method.";
}
?>
