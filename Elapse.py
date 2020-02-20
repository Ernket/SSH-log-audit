import re
import sys

#获取文件名
filename = sys.argv[1]

success_record=[]
failed_record=[]

def search(filename):
    global success_record,failed_record #全局变量
    pattern=re.compile(r': (.*?) password for (.*?) from (.*?) port (\d+)') #正则规则
    file=open(filename,'r') #打开文件
    for i in file:
        check_login=pattern.search(i) # 正则匹配
        if check_login: # 检查是否匹配到内容，如果没有就下一条
            if check_login.group(1)=="Accepted": # 成功登录
			#这里的.group(0)是原文，.group(2)为用户名，.group(3)为登录的IP地址，.group(4)为对方的端口
                success_record.append([check_login.group(2),check_login.group(3),check_login.group(4)])
            elif check_login.group(1)=="Failed": # 失败登录
                if "invalid user" in check_login.group(2):  #用户名会因为黑客测试无效用户而变得多余，所以删掉多余的部分
                    failed_record.append([check_login.group(2)[13:],check_login.group(3),check_login.group(4)])
                else:
                    failed_record.append([check_login.group(2),check_login.group(3),check_login.group(4)])
        else:
            continue

def printdata():
    global success_record,failed_record
    if success_record: #先判断是否存在内容
        print("[+] 已找到成功的记录"+str(len(success_record))+"条")
        for i in success_record:
            print("        用户名: "+i[0]+" 登录IP: "+i[1]+" 连接端口: "+i[2])
    else:
        print("[-] 无SSH登录成功的记录...")
    if failed_record:
        print("\n[+] 已找到失败的记录"+str(len(failed_record))+"条")
        for i in failed_record:
            print("        用户名: "+i[0]+" 登录IP: "+i[1]+" 连接端口: "+i[2])
    else:
        print("\n[-] 无SSH登录失败的记录...")

search(filename)
printdata()