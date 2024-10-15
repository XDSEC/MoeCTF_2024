<?php
error_reporting(0);
session_start();
    $flag = "moectf{test}";
    $username = $_POST["username"];
    $pwd = $_POST['password'];
    $sql = "SELECT * FROM user WHERE username='$username' AND `password`='$pwd'";
    $conn = mysqli_connect("localhost","root","root","ezlogin",3306);


    $result = mysqli_query($conn,$sql);
    $row = mysqli_fetch_array($result);
    if($row){
        echo "登陆成功！这是你的 flag：" . $flag;
    } else{
        echo "用户名或密码错误！";
    }


?>
