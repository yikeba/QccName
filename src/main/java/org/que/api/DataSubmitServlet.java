package org.que.api;


import jakarta.servlet.ServletException;
import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

@WebServlet(name = "DataSubmitServlet", urlPatterns = "/v1/data/submit")
public class DataSubmitServlet extends HttpServlet {

    @Override
    protected void doPost(HttpServletRequest req,
                          HttpServletResponse resp)
            throws ServletException, IOException {
        resp.setContentType("application/json;charset=utf-8");
        // 1. 读取全部请求体（设备提交的数据）
        byte[] body = req.getInputStream().readAllBytes();
        String jsonInput = new String(body, "UTF-8");
        System.out.println("收到设备数据: " + jsonInput);
        //这里我会加一个静态类，的接受方法，或定一个实例化类
        //这里调用方法处理数据，返回string 在 回写
        // 2. 当前阶段先回显（证明 API 正常）
        String jsonOutput = "{ \"status\": \"received\", \"echo\": " + jsonInput + " }";
        resp.getWriter().write(jsonOutput);
    }
}

