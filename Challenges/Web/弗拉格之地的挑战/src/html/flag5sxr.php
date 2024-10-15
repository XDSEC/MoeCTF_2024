<head>
    <title>flag5</title>
    <meta charset="UTF-8">

</head>
<body>
<p>恭喜你们已经获得了四颗龙珠，还有一半就集齐了！</p>
<p>想必你已经知道，前端不靠谱了</p>
<p>现在，我们来加深一下印象：</p>
<form name="form" action="flag5sxr.php" onsubmit="return checkValue()" method="post">
    请输入 "I want flag" : <input type="text" name="content"><br>
    <input type="submit" value="提交">

</form>

</body>
<script>
    function checkValue() {
        var content = document.forms["form"]["content"].value;
        if (content == "I want flag") {
            alert("你就这么直接？");
            return false;
        } else {
            return true;
        }
    }
</script>
<?php
if (isset($_POST['content'])) {
    $flag = 'flag5: fSV90aDF';
    if ($_POST['content'] == "I want flag") {
        echo "<p>恭喜，我相信你已经深刻了解了前端不可信任的道理!</p>";
        echo "<p>flag5: fSV90aDF</p>";
        echo "<a href='flag6diw.php'>前往下一关</a>";
    } else {
        echo "<p>抱歉，你输入的内容不对</p>";
    }
}
