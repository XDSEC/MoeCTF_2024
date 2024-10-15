package top.sxrhhh.servlet;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * TODO
 * <p>
 *
 * @author sxrhhh
 * 创建于: 2024/4/6 上午10:50
 * @version 1.0
 * @since 1.8
 */
public class HelloServlet extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {

        ServletContext context = this.getServletContext();

        String username = "Sxrhhh";
        context.setAttribute("username", username); // 将一个数据保存在了ServletContext中


        System.out.println("hello");
    }
}
