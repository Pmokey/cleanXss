# cleanXss
XSS漏洞修复工程


#######更新步骤#######
1、在eportal工程新建文件夹com.huilan.eps.apply.filter

2、把编译好的过滤器class
WebContent\WEB-INF\classes\com\huilan\eps\apply\filter\XssFilter.class
放到第一步的文件夹中

3、修改eportal的web.xml文件，添加过滤器，在web-app节点加入以下内容即可
  <!-- XSS过滤器 -->
	<filter>
		<filter-name>XssFilter</filter-name>
		<filter-class>com.huilan.eps.apply.filter.XssFilter</filter-class>
	</filter>
	<filter-mapping>
		<filter-name>XssFilter</filter-name>
		<url-pattern>/eportal/admin</url-pattern>
	</filter-mapping>
