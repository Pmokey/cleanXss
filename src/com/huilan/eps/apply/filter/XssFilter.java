package com.huilan.eps.apply.filter;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang.StringUtils;

/**
 * 
 * ClassName: XssFilter 
 * @Description: XSS过滤器
 * @date 2019年2月13日
 */
public class XssFilter implements Filter {

    /**
     * 需要过滤的地址，存在相对应地址才会过滤检查
     */
    private List<String> includeUrls = new ArrayList<String>();

    @Override
    public void destroy() {
        // TODO Auto-generated method stub
    }

    @Override
    public void doFilter(ServletRequest arg0, ServletResponse arg1, FilterChain arg2)
            throws IOException, ServletException {
        HttpServletRequest req = (HttpServletRequest) arg0;
        HttpServletResponse response = (HttpServletResponse) arg1;
        String pathInfo = req.getPathInfo() == null ? "" : req.getPathInfo();
        String url = req.getServletPath() + pathInfo;
        // 获取请求所有参数，校验防止SQL注入，防止XSS漏洞
        Enumeration<?> params = req.getParameterNames();
        String paramN = null;

        // 是否检测参数
        boolean ischeck = false;
        while (params.hasMoreElements()) {
            paramN = (String) params.nextElement();
            String paramVale = req.getParameter(paramN);
            if (includeUrls.contains(paramVale)) {
                ischeck = true;
            }
        }
        if (ischeck) {
         // 获取请求所有参数，校验防止SQL注入，防止XSS漏洞
            Enumeration<?> tparams = req.getParameterNames();
            while (tparams.hasMoreElements()) {
                paramN = (String) tparams.nextElement();
                String paramVale = req.getParameter(paramN);
                // 校验是否存在SQL注入信息
                if (checkSQLInject(paramVale, url)) {
                    errorResponse(response, paramN);
                    return;
                }
            }
        }
        arg2.doFilter(req, response);
    }

    @Override
    public void init(FilterConfig arg0) throws ServletException {
        // TODO Auto-generated method stub
        includeUrls.add("/media/img-lib!scanCodeUpload.action");
    }


    /**
     * 
     * @Description: 检查xss字段
     * @param @param str
     * @param @param url
     * @param @return   
     * @return boolean  true-存在xss字段；false-不存在xss
     * @throws
     * @date 2019年2月13日
     */
    public static boolean checkSQLInject(String str, String url) {
        if (StringUtils.isEmpty(str)) {
            return false;// 如果传入空串则认为不存在非法字符
        }

        // 判断黑名单
        String[] inj_stra = { "script", "mid", "master", "truncate", "insert", "select", "delete", "update", "declare",
                "iframe", "'", "onreadystatechange", "alert", "atestu", "xss", ";", "'", "\"", "<", ">", "(", ")", ",",
                "\\", "svg", "confirm", "prompt", "onload", "onmouseover", "onfocus", "onerror" };

        str = str.toLowerCase(); // sql不区分大小写

        for (int i = 0; i < inj_stra.length; i++) {
            if (str.indexOf(inj_stra[i]) >= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * 
     * @Description: 输出错误信息
     * @param @param response
     * @param @param paramNm
     * @param @throws IOException   
     * @return void  
     * @throws
     * @date 2019年2月13日
     */
    private void errorResponse(HttpServletResponse response, String paramNm) throws IOException {
        String warning = "输入项中不能包含非法字符。";
        response.setContentType("text/html; charset=UTF-8");
        PrintWriter out = response.getWriter();
        out.println("{\"msg\":\"" + warning + "\", \"fieldName\": \"" + paramNm + "\"}");
        out.flush();
        out.close();
    }
}
