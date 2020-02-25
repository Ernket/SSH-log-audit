import re
import sys
from collections import Counter

#获取文件名
filename = sys.argv[1]

success_record=[]
failed_record=[]
success_ip=[]
failed_ip=[]
month={"Jan":"一月","Feb":"二月","Mar":"三月","Apr":"四月","May":"五月","Jun":"六月","Jul":"七月","Aug":"八月","Sept":"九月","Oct":"十月","Nov":"十一月","Dec":"十二月"}



def search():
    global success_record,failed_record,filename #全局变量
    pattern=re.compile(r'(.*?) (\d+) (.*?) .*?: (.*?) password for (.*?) from (.*?) port (\d+)') #正则规则
    file=open(filename,'r') #打开文件
    for i in file:
        check_login=pattern.search(i) # 正则匹配
        if check_login: # 检查是否匹配到内容，如果没有就下一条
            if check_login.group(4)=="Accepted": # 成功登录
			#这里的.group(0)是原文，.group(1、2、3)均为日期，.group(5)为用户名,6是登录的IP地址，.group(7)为对方的端口
                success_record.append([check_login.group(1),check_login.group(2),check_login.group(3),check_login.group(5),check_login.group(6),check_login.group(7)])
            elif check_login.group(4)=="Failed": # 失败登录
                if "invalid user" in check_login.group(5):  #用户名会因为黑客测试无效用户而变得多余，所以删掉多余的部分
                    failed_record.append([check_login.group(1),check_login.group(2),check_login.group(3),check_login.group(5)[13:],check_login.group(6),check_login.group(7)])
                else:
                    failed_record.append([check_login.group(1),check_login.group(2),check_login.group(3),check_login.group(5),check_login.group(6),check_login.group(7)])
        else:
            continue

def writeANDprint_data(month,filename,success_ip,failed_ip):
    global success_record,failed_record
    wfile=open("result.txt","w")
    wfile.write("分析文件："+filename+"\n")
    if success_record: #先判断是否存在内容
        wfile.write("[+] 已找到成功的记录"+str(len(success_record))+"条\n")
        print("[+] 已找到成功的记录"+str(len(success_record))+"条")
        for i in success_record:
            print("        登录时间: "+month[i[0].rstrip()]+i[1]+"号 "+i[2]+" 用户名: "+i[3]+" 登录IP: "+i[4]+" 连接端口: "+i[5])
            wfile.write("        登录时间: "+month[i[0].rstrip()]+i[1]+"号 "+i[2]+" 用户名: "+i[3]+" 登录IP: "+i[4]+" 连接端口: "+i[5]+"\n")
            success_ip.append(i[4])
    else:
        print("[-] 无SSH登录成功的记录...")
        wfile.write("[-] 无SSH登录成功的记录...\n")
    if failed_record:
        print("\n[+] 已找到失败的记录"+str(len(failed_record))+"条")
        wfile.write("\n[+] 已找到失败的记录"+str(len(failed_record))+"条\n")
        for i in failed_record:
            wfile.write("        登录时间: "+month[i[0].rstrip()]+i[1]+"号 "+i[2]+" 用户名: "+i[3]+" 登录IP: "+i[4]+" 连接端口: "+i[5]+"\n")
            print("        登录时间: "+month[i[0].rstrip()]+i[1]+"号 "+i[2]+" 用户名: "+i[3]+" 登录IP: "+i[4]+" 连接端口: "+i[5])
            failed_ip.append(i[4])
    else:
        print("\n[-] 无SSH登录失败的记录...")
        wfile.write("\n[-] 无SSH登录失败的记录...\n")
    scst=Counter(success_ip)
    fdst=Counter(failed_ip)
    wfile.write("结果统计：\n  成功的记录统计：\n")
    for i in scst.keys():
        print("IP地址: "+i+" 找到的记录有"+str(scst[i])+"次")
        wfile.write("    IP地址: "+i+" 找到的记录有"+str(scst[i])+"次\n")
    wfile.write("  失败的记录统计：\n")
    for i in fdst.keys():
        print("IP地址: "+i+" 找到的记录有"+str(fdst[i])+"次")
        wfile.write("    IP地址: "+i+" 找到的记录有"+str(fdst[i])+"次\n")
    wfile.close

search()
writeANDprint_data(month,filename,success_ip,failed_ip)
