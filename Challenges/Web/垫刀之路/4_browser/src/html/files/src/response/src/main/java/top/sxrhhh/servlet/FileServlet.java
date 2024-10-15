package top.sxrhhh.servlet;

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URLEncoder;

/**
 * TODO
 * <p>
 *
 * @author sxrhhh
 * 创建于: 2024/4/6 下午7:28
 * @version 1.0
 * @since 1.8
 */
public class FileServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        // 1. 要获取下载文件的路径
//        String realPath = this.getServletContext().getRealPath("/home/sxrhhh/code/java/javaweb-02-servlet/response/target/classes/你好.png");
        String realPath = "/home/sxrhhh/code/java/javaweb-02-servlet/response/target/classes/你好.png";
        System.out.println("下载文件的路径：" + realPath);
        // 2. 下载的文件名
        String filename = realPath.substring(realPath.lastIndexOf("/") + 1);
//        System.out.println(filename);
        // 3. 设置让浏览器能够支持下载文件
        resp.setHeader("Content-Disposition", "attachment;filename=" + URLEncoder.encode(filename, "UTF-8"));
        // 4. 获取下载文件的输入流
        FileInputStream fis = new FileInputStream(realPath);
        // 5. 创建缓冲区
//        resp.getWriter().println("hhh");
        int len = 0;
        byte[] buffer = new byte[1024];
        // 6. 获取OutputStream对象
        ServletOutputStream out = resp.getOutputStream();
        // 7. 将FileOutputStream 流写入到 buffer 缓冲区,使用OutputStream将缓冲区中的数据输出到客户端
        while ((len = fis.read(buffer)) != -1) {
            out.write(buffer, 0, len);
        }
        // 8. 关闭流
        fis.close();
        out.close();

    }


    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }
}
