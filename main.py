import click
from modules.Main import Main
from colorama import init, Fore
@click.command()
@click.version_option(version='1.0')
@click.option("-u", "--url", help="输入url,例如：http://baidu.com", default='', is_eager=True)
@click.option("-f", "--file", help="从文件加载url列表", default='')
@click.option("-t", "--threads", show_default=True, default=100, help="定义扫描的线程")
@click.option("-l", "--list", help="列出所有POC", is_flag=True)
@click.option("-lc", "--list-cms", help="列出指定组件的漏洞", default='')
@click.option("-p", "--poc", help="指定poc进行测试，输入文件名", default='')
@click.option("-c", "--cms", help="指定组件进行测试，输入组件名称", default='')
@click.option("--txt", help="输出扫描结果（txt）", default='')
@click.option("--html", help="输出扫描结果（html）", default='')
@click.option("-to", "--timeout", help="设置超时时间", default=2, show_default=True)
@click.option("--debug", help="显示Debug信息", default=False,is_flag=True)
@click.option("--show-all-result", help="显示所有结果", default=False,is_flag=True)

def click_main(url, file, poc,cms,threads,list, list_cms,txt, html,timeout,debug,show_all_result):
    click.echo(Fore.CYAN + '''[#] poc-yaml-test by qianxiao996''')
    main = Main(threads,txt, html,timeout,debug,show_all_result)
    main.chuli_canshu(url, file, poc,cms,list,list_cms)
if __name__ == '__main__':
    init(autoreset=False)
    click_main()
