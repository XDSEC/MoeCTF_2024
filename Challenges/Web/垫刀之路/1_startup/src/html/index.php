<html>
<head>
    <meta charset="UTF-8">
    <title>MoeCTF? 启动！</title>
    <script src="jquery.js"></script>
</head>
<body>

<p>在开始 MoeCTF 的旅程之前，我们先来体验一下黑入一台电脑的感觉</p>
<p>RCE, 又名远程命令执行漏洞，当你获得了目标机器的命令执行权限之后，你就可以获得你想要的 flag</p>
<p>现在，你已经 getshell 了，在这里获得你的 flag 吧</p>
<p>下面是一个命令执行框，在这里你可以执行任何你想要执行的系统命令:</p>

<!--禁止回车提交表单-->
<form id="form" onsubmit="return false">
    <label for="command">在此输入命令: </label>
    <input id="command" type="text" name="command">
    <input id="submit" type="button" value="执行" onclick="exec()">
</form>

<br/>
<div id="result">
    <p>执行结果：</p>
    <span id="span_result"></span>
</div>

<script>
    function exec() {
        $.ajax({
            type: "post",
            dataType: "text",
            url: "cmd.php",
            data: $('#form').serialize(),
            success: function (result) {
                console.log(result)
                $('#span_result').html(result)
            },
            error: function (result) {
                console.log(result)
                $('#span_result').html(result)
            },
        });
    }
</script>


</body>
</html>




