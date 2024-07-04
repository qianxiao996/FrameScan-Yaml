## 工具介绍

使用Python编写的扫描框架。仅支持yaml格式。

## 工具使用

```python
Usage: poc_test.exe [OPTIONS]

Options:
  --version               Show the version and exit.
  -u, --url TEXT          输入url,例如：http://baidu.com
  -f, --file TEXT         从文件加载url列表
  -t, --threads INTEGER   定义扫描的线程  [default: 100]
  -l, --list              列出所有POC
  -lc, --list-cms TEXT    列出指定组件的漏洞
  -p, --poc TEXT          指定poc进行测试，输入文件名
  -c, --cms TEXT          指定组件进行测试，输入组件名称
  --txt TEXT              输出扫描结果（txt）
  --html TEXT             输出扫描结果（html）
  -to, --timeout INTEGER  设置超时时间  [default: 2]
  --debug                 显示Debug信息
  --show-all-result       显示所有结果
  --help                  Show this message and exit.
```

## Yaml插件编写

本插件参考Xray插件格式 。使用Python实现。

### 基础的 YAML 插件

```yaml
#插件名称
name: poc-yaml-example-com
# 脚本部分
transport: http
rules:
  r1:
    request:
      method: GET
      path: /
      body: addd $num
      headers:
        Content-Type: application/json
    expression: |
      response.status_code==200 && operator.contains(response.text,'html')
    output:
      serial: re.search('\w+',response.text).group()
      html: re.search('refresh',response.text).group()
expression: r1 && r2
#信息部分
detail:
  author: qianxiao996
  vuln_id: cve-2019-2222
  description: '111'
  category: 敏感信息泄露
  subassembly: ALL
  links:
    - http://example.com
#全局变量
set:
  a: 1
  num: randint(1000, 2000)
```

整个 YAML 插件大致可以分为 3 部分：

- 名称： 脚本名称, string 类型
- 脚本部分：主要逻辑控制部分，控制着脚本的运行过程
- 信息部分：主要是用来声明该脚本的一些信息，包括输出内容

### YAML插件的脚本部分

#### 传输方式（transport）暂时 只实现了http协议。

该字段用于指定发送数据包的协议。 `transport： string`

形如：

```yaml
transport: http
```

目前 transport 的取值可以为以下 3 种之一：

1. tcp
2. udp
3. http

目前不允许一个脚本中发送不同种 transport 的请求，因为通常我们的输入是一个稳定的协议， 比如：

1. 端口存活探测的结果通常会知道它是 tcp 或者 udp 存活
2. 或者从一个明确的 http 请求或者 web 站点开始

#### YAML插件主体的关键字的意义

```yaml
rules:
  r1:
    request:
      method: GET
      path: /
      body: addd $num
      headers:
        Content-Type: application/json
    expression: |
      response.status_code==200 && operator.contains(response.text,'html')
    output:
      serial: re.search('\w+',response.text).group()
      html: re.search('refresh',response.text).group()
  r2:
    request:
      method: GET
      path: /
      body: aaa $html aaaa
      headers:
        Content-Type: application/json $html
    expression: |
      response.status_code==200 && operator.contains(response.text,'html')
    output:
      serial: re.search('\w+',response.text).group()
      html: re.search('refresh',response.text).group()
expression: r1 && r2
```

1. rules以及单个rule的名称
   
   - **rules**代表着一个规则集，在这个规则集中，将存放着所有要发送的信息以及要判断的规则
   - **rule**则是一个请求的规则，代表你想要发送什么样的请求。如上述所举的例子中，r1,r2是规则的名称

2. request
   
   该关键词中存在着构建一个请求包所要填写的信息，包括请求使用的方法，请求路径，请求头，请求body，是否跟随302跳转。
   
   - `method: string` 请求方法
   - `path: string` 请求的完整 Path，包括 querystring 等 
     1. 如果 path 是以 `/` 开头的， 取 dir 路径拼接
     2. 如果 path 是以 `^` 开头的， uri 直接取该路径
     3. 其他则拼接uri+"/"+path
   - `headers: map[string]string` 请求 HTTP 头，Rule 中指定的值会被覆盖到原始数据包的 HTTP 头中
   - `body: string` 请求的Body
   - `follow_redirects: bool` 是否允许跟随300跳转, 默认为true

3. expression
   
   在rule下的`expression`是用来对返回包（response）进行匹配的，你可以编写各种各样的限制来判断返回包中信息，从而确认返回的内容是否符合要求。此处将作为python代码来执行，并内置了requests模块的response对象，内置引入了operator模块，可直接使用。
   
   以下为示例表达式
   
   ```python
   #使用正则表达式匹配
   re.search('\w+',response.text).group()
   #判断返回body中包含某个字符串
   operator.contains(response.text,'html')
   #判断返回状态码
   response.status_code==200
   #组合使用 判断返回状态码为200且返回body中包含html
   response.status_code==200 && operator.contains(response.text,'html')
   ```
   
   4.output

参照set的设置与使用

#### 与rules同级的expression的使用

对于脚本层级的 expression，这个结果作为最后脚本是否匹配成功的值，通常脚本层级的 expression 是 rule 结果的一个组合。 比如一个脚本包含 `r1`, `r2`, `r3`，`r4` 4 条规则， 作为脚本层级的 expression，其全局变量将会定义 `r1`, `r2`, `r3`， `r4` 4 个函数，调用这个 4 个函数即可获得它对应 rule 的结果。

```yaml
expression: r1 && r2 && r3 && r4
```

#### set关键字的使用

该字段主要是用来定义一些在接下来的规则中会使用到的一些全局变量，比如随机数，反连平台等。 `set: map[string]interface{}`

```yaml
set:
    a: 1
    num: randint(1000, 2000)      # 1543
    rstr: ''.join(random.sample(string.ascii_lowercase, 10))   # thkpznlbsi
```

set设置的变量与output匹配的变量可直接在request的path、headers、body中使用。如上述的使用方式为

```yaml
rules:
  r1:
    request:
      method: GET
      path: /$a
      body: addd $num
      headers:
        Content-Type: application/json $rstr
```

#### output组合使用

1. 获取返回的token
2. 获取上传文件后返回的文件路径
3. 总结：获取所需要的参数

返回包

```http
HTTP/1.1 200 OK
Content-Type: application/json; charset=utf-8;

{"pbx":"COMpact 4000","pbxType":20,"pbxId":0,"serial":"4107646840","date":"05.07.2022","macaddr":"00:01:01:01:01:01"}
```

匹配

```yaml
rules:
    r1:
        request:
            method: GET
            path: "/about_state"
        expression: response.status == 200 
        output:
            pbx: re的正则表达式 #
    r2:
        request:
            method: GET
            path: "/about_state"
            body: a=$pbx&b=1
        expression: response.status == 200
```

#### 与rules同级的output

该output为漏洞输出的提示信息。

可使用的格式为`{{python代码}}$a `  `$a`为set获取

```
rules:
    r1:
        request:
            method: GET
            path: "/about_state"
        expression: response.status == 200 
        output:
            pbx: re的正则表达式 #
    r2:
        request:
            method: GET
            path: "/about_state"
            body: a=$pbx&b=1
        expression: response.status == 200
output: 卧槽发现漏洞了{{re.search('\w+',response.text).group()}} $num
set:
  a: "''.join(random.sample(string.ascii_lowercase, 10))"
  num: randint(1000, 2000)
```

#### 全局变量self.poc

可利用poc打印所有的数据。此处output将显示`/%2e/WEB-INF/web.xml` 推荐使用`test{{self.poc.get('rules').get('r1').get('request').get('path')}}`取值

```yaml
name: poc-yaml-xxxxx
transport: http
rules:
  r1:
    request:
      method: GET
      path: /%2e/WEB-INF/web.xml
      headers:
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36
    expression: |
      response.status_code==200 && operator.contains(response.text,'<web-app>')
output: test{{self.poc['rules']['r1']['request']['path']}}
expression: r1() || r2() || r3() || r4() || r5()
detail:
  author: jetty web.xml敏感信息泄露
  vuln_id: 
  description: 'jetty web.xml敏感信息泄露'
  links: []
```

#### payload

与set变量一致，但值不会当作代码执行而是直接进行字符串替换。

```yaml
payload:
  expression: |
    "response.status_code==200 && (re.search('Index of /',str(response.text))|| re.search('Directory: /',str(response.text))||re.search(' - /</title>',str(response.text)))"
detail:
  name: '目录浏览漏洞'
  author: qianxiao996
  category: 目录浏览
  vuln_id: 无
  description: '目录浏览'
  links: []
```

### YAML插件的信息部分

该字段用于定义一些和脚本相关的信息。

目前主要定义了一下几个部分：

```yaml
detail:
  name: #中文的漏洞名称
  author: # 作者（个人主页）
  vuln_id: #漏洞编号
  category: #分类
  subassembly: #组件，例如通达OA
  links:
    - # 参考链接
    - # 可以是多个链接
  description: # 对该poc/漏洞的描述
```
