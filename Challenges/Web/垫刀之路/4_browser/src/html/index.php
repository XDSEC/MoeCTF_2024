<?php

if (isset($_GET['path'])) {
    $directory = $_GET['path']; // 你想列出文件的目录
} else {
    $directory = "";
}

//$directory = $_GET['filename']; // 你想列出文件的目录

// 直接使用用户输入的文件名，没有过滤或验证
$filepath = "/var/www/html/files/" . $directory ;
// $filepath = "/home/sxrhhh/code/create-ctf/24moe/levelup_road/4_browser/files" . $directory;

//echo $filepath;
//echo "<br/>";
if (!file_exists($filepath)) {
    die("no such file");
}

if (!is_dir($filepath)) {

    echo "文件内容：<br/>";
    echo nl2br(htmlspecialchars(file_get_contents($filepath)));
    die();
}

if (is_dir($filepath)) {

    $files = scandir($filepath);

    echo "<h1>Directory: " . htmlspecialchars($directory) . "</h1>";
    echo "<ul>";
    foreach ($files as $file) {
        if ($file == '.' || $file == '..') continue;
        $fullPathFile = $filepath . '/' .  $file;
        $isDir = is_dir($fullPathFile);
        $link = htmlspecialchars($directory . '/' . $file);
        echo "<li><a href='?path=$link'>" . htmlspecialchars($file) . ($isDir ? ' (Directory)' : '') . "</a></li>";
    }
    echo "</ul>";


//    echo 1;
}


?>
