<head>
    <title>flag6</title>
    <meta charset="UTF-8">
</head>
<p>恭喜你已经突破了前端的限制，可以来看一个经典的后端语言：php</p>
<p>不难哦，只要能看懂就行了</p>
<?php
highlight_file("flag6src.txt");
if (isset($_GET['moe']) && $_POST['moe']) {
    if (preg_match('/flag/', $_GET['moe'])) {
        die("no");
    } elseif (preg_match('/flag/i', $_GET['moe'])) {
        echo "flag6: rZV9VX2t<br>";
        echo "<a href='flag7fxxkfinal.php'>前往下一关</a>";
    }
}

