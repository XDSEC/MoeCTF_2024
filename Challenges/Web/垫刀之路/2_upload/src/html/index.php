<html>
<head>
    <meta charset="UTF-8">
    <title>文件上传</title>
    <script src="jquery.js"></script>
</head>
<body>

<form action="index.php" method="post">

    <input type="file" id="imageInput" name="image" >

    <img id="preview" src="#" alt="图片预览" style="display: none; width: 300px; height: auto">

    <input id="btn" type="button" value="上传图片">

</form>

<br/>

<span id="result"></span>







<script>
    $("#imageInput").change(function () {
        console.log("onchange");
        const input = $("#imageInput")[0];
        if (input.files && input.files[0]) {
            const reader = new FileReader();
            reader.onload = function (e) {
                const prev = $("#preview");
                prev.attr("src", e.target.result);
                // prev.src = e.target.result;
                // prev.show();
                prev.css("display", "block");
                // prev.style.display = "block"; // 显示图片
            };

            // 读取文件内容
            reader.readAsDataURL(input.files[0]);
        }
    })

    $("#btn").click(function () {
        // console.log("onclick");
        const input = $("#imageInput")[0];
        if (input.files && input.files[0]) {
            const formData = new FormData();
            formData.append("image", input.files[0]);
            $.ajax({
                url: "upload.php",
                type: "POST",
                data: formData,
                processData: false, // 告诉jQuery不要处理发送的数据
                contentType: false, // 告诉jQuery不要设置contentType
                success: function (res) {
                    console.log(res);
                    $("#result").text(res);
                }
            })
        }
    })

</script>

</body>
</html>




