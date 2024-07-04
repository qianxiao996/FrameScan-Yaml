import sys,threading,eventlet
from prettytable import PrettyTable
import sqlite3,os,yaml,queue
from colorama import  Fore
from tqdm import tqdm

from modules.Class_Poc import Class_Poc
Plugins_path = "plugins"
class Main:
    def __init__(self,threads,txt, html,timeout,debug,show_all_result):
        self.portQueue = queue.Queue()  
        self.out_txt=txt
        self.out_html = html
        self.all_url = []
        self.all_poc = []
        self.threadnum=threads
        self.timeout = timeout
        self.debug=debug
        #显示所有结果 默认只显示成功的
        self.show_all_result =show_all_result
    def chuli_canshu(self,url, file,poc,cms,list_flag,list_cms):
        if url and file:
            click.echo(Fore.RED + "[E] 不能同时输入URL和文件参数！")
            sys.exit()
        if poc and cms:
            click.echo(Fore.RED + "[E] 不能同时使用--poc和--poc参数！")
            sys.exit()
        if list_flag:
            table,all_poc = self.list_all_vuln()
            print(table)
            return
        if list_cms:
            table,all_poc = self.list_all_vuln(list_cms)
            print(table)
            return
        if poc:
            self.all_poc.append(self.get_single_poc_yaml(poc))
        elif cms:
            table,all_poc = self.list_all_vuln(cms)
            self.all_poc = all_poc
        else: 
            table,all_poc = self.list_all_vuln()
            self.all_poc = all_poc
        if  self.out_txt: 
            self.out_txt = open(self.out_txt, "w",encoding="utf-8")
            self.out_txt.write("URL地址\t漏洞名称\tPOC名称\t结果\t其他信息\n")
        if self.out_html:
            self.out_html = open(self.out_html, "w",encoding="utf-8")
            self.out_html.write("URL地址\t漏洞名称\tPOC名称\t结果\t其他信息\n")
        if file:
            self.all_url = self.read_file_to_list(file)
        else:
            if url and (url.startswith("http://") or url.startswith("https://")):
                self.all_url.append(url)
        if len(self.all_url)>0 and len(self.all_poc)>0:
            self.put_portQueue()
        else:
            tqdm.write(Fore.RED+"[E] URL或POC为空！")
    def put_portQueue(self):
        tqdm.write("[*] 正在创建队列...")
        for url in self.all_url:
            for poc in self.all_poc:
                self.portQueue.put({"url":url, "poc":poc})
        tqdm.write("[*] 队列创建完成！")
        if self.threadnum > self.portQueue.qsize():
            self.threadnum = self.portQueue.qsize()
        if self.threadnum > 1000:
            self.threadnum = 1000
        self.start()
    def poc_start(self,pbar):
        while True:
            try:
                if self.portQueue.qsize()<=0:
                    break
                else:
                    eventlet.monkey_patch(thread=False, time=True)
                    with eventlet.Timeout(120, False):
                        if self.portQueue.empty():  # 队列空就结束
                            break
                        url_poc = self.portQueue.get()
                        url = url_poc.get("url")
                        poc = url_poc.get("poc")
                        # pbar.set_description(Fore.BLUE + '[*] Scanning:' +url)  # 修改进度条描述
                        pbar.update(1)
                        # print(host,port)
                        try:
                            poc_obj  = Class_Poc(url,poc,self.timeout,self.debug)
                            result = poc_obj.main()
                            self.out_result(result.get("url"),result.get("poc"),result.get("result"),result.get("others"))
                        except Exception as e:
                            tqdm.write(Fore.RED+"[E] "+str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                            continue
            except Exception as e:
                tqdm.write(Fore.RED+"[E] "+str(e) + '----' + str(e.__traceback__.tb_lineno) + '行')
                continue
    def out_result(self,url,poc,result,others):
        zh_cn_name = poc.get("detail").get("name")
        name = poc.get("name")

        if result:
            if self.out_txt:
                self.out_txt.write("%s\t%s\t%s\t%s\t%s\n"%(str(url).strip(),str(zh_cn_name).strip(),str(name).strip(),str(result).strip(),str(others).strip()))
            if self.out_html:
                self.out_html.write("%s\t%s\t%s\t%s\t%s\n"%(str(url).strip(),str(zh_cn_name).strip(),str(name).strip(),str(result).strip(),str(others).strip()))
            tqdm.write(Fore.GREEN + '[+] ' +Str_Align(str(url).strip(),35)+ Str_Align(str(zh_cn_name).strip(),30)+  Str_Align(str(name).strip(),35) +  Str_Align(str(result).strip(),12)   + Str_Align(str(others).strip(),10))
        # else:
        elif self.show_all_result or self.debug:
            if self.out_txt:
                self.out_txt.write("%s\t%s\t%s\t%s\t%s\n"%(url,zh_cn_name,name,result,others))
            if self.out_html:
                self.out_html.write("%s\t%s\t%s\t%s\t%s\n"%(url,zh_cn_name,name,result,others))
            tqdm.write(Fore.WHITE + '[-] ' +Str_Align(str(url).strip(),35)  +  Str_Align(str(zh_cn_name).strip(),30) + Str_Align(str(name).strip(),35) +  Str_Align(str(result).strip(),12)  + Str_Align(str(others).strip(),10)  )
        else:
            pass
    def start(self):
        tqdm.write(Fore.YELLOW+"[*] POC数量:%s URL数量:%s 线程:%s 开始扫描..."%(str(len(self.all_poc)),str(len(self.all_url)),str((self.threadnum))))
        try:
            count=self.portQueue.qsize()
            with tqdm(total=count, ncols=100) as pbar:
                tqdm.write(Fore.CYAN + '[*] ' + Str_Align('URL地址',35) +  Str_Align('漏洞名称',30) +Str_Align('POC名称',35) +   Str_Align("结果",12)  +     Str_Align("其他信息",10))
                if self.portQueue.qsize() > 0:
                    try:
                        # self.poc_start(pbar)
                        threads_list = []  # 线程列表
                        for i in range(self.threadnum):
                            i = threading.Thread(target=self.poc_start, args=(pbar,))
                            threads_list.append(i)
                        for t in threads_list:  # 启动线程
                            t.start()
                        for t in threads_list:  # 阻塞线程，等待线程结束
                            t.join()
                    except KeyboardInterrupt:
                        self.portQueue.queue.clear()
                        tqdm.write(Fore.RED + "用户中途退出！")
                        return
                tqdm.write(Fore.YELLOW + '[#] 扫描完成!')
                pbar.set_description(Fore.BLUE + '[*] Scan Complete!')  # 修改进度条描述
                try:
                    self.out_txt.close()
                    self.out_html.close()
                except:
                    pass
                pbar.close()
        except KeyboardInterrupt:
            tqdm.write(Fore.RED + "用户中途退出！")
            pass

    def get_single_poc_yaml(self,filename):
        if filename.endswith("yaml"):
            f= open(Plugins_path+"/"+filename, 'r', encoding='utf-8')
            data = yaml.load(stream=f, Loader=yaml.FullLoader)
            f.close()
            return data
        else:
            click.echo(Fore.RED + "[E] 该POC不存在或不是yaml结尾！")
            sys.exit() 
    # 列出所有的漏洞
    def list_all_vuln(self,cms='all'):
        all_poc = []
        table = PrettyTable([Fore.CYAN + ('漏洞类型'),Fore.CYAN + ('漏洞名称'),Fore.CYAN + ('影响组件'),Fore.CYAN + ('插件名称'), Fore.CYAN + ('插件作者'), Fore.CYAN + ('漏洞编号')])
        files = os.listdir(Plugins_path)
        for file in files:
            if file.endswith("yaml"):
                f= open(Plugins_path+"/"+file, 'r', encoding='utf-8')
                data = yaml.load(stream=f, Loader=yaml.FullLoader)
                f.close()
                if cms=="all" or  cms == data.get("detail").get("subassembly")  :
                    table.add_row([data.get("detail").get("category"),data.get("detail").get("name"),data.get("detail").get("subassembly"),data.get("name"),data.get("detail").get("author"),data.get("detail").get("vuln_id")])
                    all_poc.append(data)
        return table,all_poc
    def read_file_to_list(self,file_path):
        all_list=[]
        if os.path.exists(file_path):
            file = open(file_path, 'r', encoding='utf-8')
            for line in file:
                if line.startswith('http://') or line.startswith('https://'):
                    all_list.append(line)
            file.close()
            return all_list
        else:
            click.echo(Fore.RED + "[E] 文件不存在！")
            sys.exit()
# def Str_Align(_string, _length, _type='L'):
    # return _string

def Str_Align(_string, _length, _type='L'):
    """
    中英文混合字符串对齐函数
    Str_Align(_string, _length[, _type]) -> str
    :param _string:[str]需要对齐的字符串
    :param _length:[int]对齐长度
    :param _type:[str]对齐方式（'L'：默认，左对齐；'R'：右对齐；'C'或其他：居中对齐）
    :return:[str]输出_string的对齐结果
    """
    _str_len = len(_string)  # 原始字符串长度（汉字算1个长度）
    for _char in _string:  # 判断字符串内汉字的数量，有一个汉字增加一个长度
        if u'\u4e00' <= _char <= u'\u9fa5':  # 判断一个字是否为汉字（这句网上也有说是“ <= u'\u9ffff' ”的）
            _str_len += 1
    _space = _length-_str_len  # 计算需要填充的空格数
    if _type == 'L':  # 根据对齐方式分配空格
        _left = 0
        _right = _space
    elif _type == 'R':
        _left = _space
        _right = 0
    else:
        _left = _space//2
        _right = _space-_left
    return ' '*_left + _string + ' '*_right
