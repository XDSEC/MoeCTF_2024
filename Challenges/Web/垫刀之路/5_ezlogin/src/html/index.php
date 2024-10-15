<html>

<head>
    <meta charset="UTF-8">
    <title>Login</title>
    <script src="jquery.js" ></script>
</head>

<body>

<form id="form" >
    <label for="lb-username">用户名</label>
    <input id="lb-username" type="text" name="username">
    <br/>
    <label for="lb-password">密码</label>
    <input id="lb-password" type="password" name="password">

    <br/>
    <input type="button" value="登录" onclick="login()">
</form>

<span id="span_result"></span>

<script>
    function login() {
        $.ajax({
            type: "post",
            dataType: "text",
            url: "login.php",
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