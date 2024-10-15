<?php
if(isset($_POST['method'])){
    if ($_POST['method'] == 'get') {
        $data = array(
            'hint' => '恭喜你！你已经知道，前端的一切都是可以更改的！',
            'fll' => 'flag4: fdFVUMHJ',
            'goto' => '前往：/flag5sxr.php',

        );
        header('Content-type: application/json');
        die(json_encode($data));
    }
}

?>
<head>
    <meta charset="UTF-8">
    <title>flag4</title>
</head>

<?php
$referer = $_SERVER['HTTP_REFERER'];
if ($referer != 'http://localhost:8080/flag3cad.php?a=1') {
    echo '啊？难道你不是从 http://localhost:8080/flag3cad.php?a=1 点击链接过来的吗？<br>';
    echo '坏了，肯定是哪里搞错了，要不你看看能不能自己临时凑合凑合？<br>';
} else {
    echo "ok, 你成功闯入了第四关！<br>";
    echo "本关考验你听声辩位的功夫，你需要按下开始按钮后，根据提示按下相应的按钮。<br>";
    $base = 'PGJ1dHRvbiBvbmNsaWNrPSJzdGFydCgpIj7lvIDlp4s8L2J1dHRvbj4KPHNwYW4gaWQ9Im51bSI+PC9zcGFuPgo8YnI+CjxkaXYgaWQ9InNjb3BlIj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjE8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjI8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjM8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjQ8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjU8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjY8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjc8L2J1dHRvbj4KICAgIDxidXR0b24gb25jbGljaz0iZ2V0SUQodGhpcykiPjg8L2J1dHRvbj4KPC9kaXY+Cgo8c2NyaXB0PgogICAgdmFyIGJ1dHRvbnMgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgic2NvcGUiKS5nZXRFbGVtZW50c0J5VGFnTmFtZSgiYnV0dG9uIik7CiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ1dHRvbnMubGVuZ3RoOyBpKyspIHsKICAgICAgICBidXR0b25zW2ldLmlkID0gaSArIDE7CiAgICB9CiAgICBmdW5jdGlvbiBzdGFydCgpIHsKICAgICAgICBkb2N1bWVudC5nZXRFbGVtZW50QnlJZCgibnVtIikuaW5uZXJUZXh0ID0gIjkiOwogICAgfQogICAgZnVuY3Rpb24gZ2V0SUQoYnV0dG9uKSB7CiAgICAgICAgaWYgKGJ1dHRvbi5pZCA9PSA5KSB7CiAgICAgICAgICAgIGFsZXJ0KCLkvaDov4flhbPvvIHvvIjpk5zkurrpnIflo7DvvIlcbuaIkeS7rOS9v+eUqCBjb25zb2xlLmxvZyDmnaXkuLrkvaDnlJ/miJAgZmxhZyIpOwogICAgICAgICAgICBmZXRjaCgnZmxhZzRiYmMucGhwJywgewogICAgICAgICAgICAgICAgbWV0aG9kOiAncG9zdCcsCiAgICAgICAgICAgICAgICBib2R5OiAnbWV0aG9kPWdldCcsCiAgICAgICAgICAgICAgICBoZWFkZXJzOiB7CiAgICAgICAgICAgICAgICAgICAgJ0NvbnRlbnQtVHlwZSc6ICdhcHBsaWNhdGlvbi94LXd3dy1mb3JtLXVybGVuY29kZWQnLAogICAgICAgICAgICAgICAgfSwKICAgICAgICAgICAgfSkudGhlbigoZGF0YSkgPT4gewogICAgICAgICAgICAgICAgcmV0dXJuIGRhdGEuanNvbigpOwogICAgICAgICAgICB9KS50aGVuKChyZXN1bHQpID0+IHsKCQkJCWNvbnNvbGUubG9nKHJlc3VsdC5oaW50KTsKICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKHJlc3VsdC5mbGwpOwogICAgICAgICAgICAgICAgY29uc29sZS5sb2cocmVzdWx0LmdvdG8pCiAgICAgICAgICAgIH0pOwogICAgICAgIH0gZWxzZSB7CiAgICAgICAgICAgIGFsZXJ0KCLor6XnvZrvvIEo5aS06YOo56Kw5pKe5aOwKSIpCiAgICAgICAgfQogICAgfQo8L3NjcmlwdD4=';
    echo base64_decode($base);
}
?>

