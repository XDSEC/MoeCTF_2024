package top.sxrhhh.servlet;

import javax.servlet.RequestDispatcher;
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
 * 创建于: 2024/4/6 上午11:28
 * @version 1.0
 * @since 1.8
 */
public class ServletDemo04 extends HttpServlet {
    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        ServletContext context = this.getServletContext();
        System.out.println("已经进入");
//        RequestDispatcher requestDispatcher = context.getRequestDispatcher("/gp"); //转发的请求路径
//        requestDispatcher.forward(req, resp); //调用forward实现请求转发
        context.getRequestDispatcher("/gp").forward(req, resp);
    }


    @Override
    protected void doPost(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
        doGet(req, resp);
    }
}
