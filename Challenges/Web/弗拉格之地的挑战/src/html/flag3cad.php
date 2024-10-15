<?php
//error_reporting(0);
setcookie("verify", "user");
header("fxxk: /flag3.php");
echo "<head><title>flag3</title></head>";
echo "<p>我想，你应该已经知道 devtools 这个东西了。(不知道也没关系，你 f12 出来的就是 devtools)</p>";
echo "<p>那么现在在你面前的有两个教程：</p>";
echo "<p>1. 尝试把 devtools 运用熟练</p>";
echo "<p>2. 尝试下载一个别的什么玩意来使用</p>";
echo "<p>这题，我们还是学习 http</p>";
echo "<p>那么，我们来试一下同时把下面要求完成吧！</p>";
echo "<p>---------------------------------------------------------------------------</p>";
echo "请用 GET 方法传入一个 a 参数<br>";
if (isset($_GET['a'])){
    echo "再用 POST 方法传入一个 b 参数<br>";
    if (isset($_POST['b'])){
        echo "你需要使用 admin 的身份验证<br>";
        echo "<!--你知道 cookie 吗？-->";
        if ($_COOKIE['verify'] == 'admin') {
            echo "恭喜你已经基本掌握了 http 的最最最基础知识，先去下一关吧<br>";
            echo "flag3: yX3RoMXN<br>";
            echo "<a href='/flag4bbc.php'>前往下一关</a><br>";

        } else {
        }

    }

}
?>


