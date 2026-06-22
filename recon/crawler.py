import subprocess
# from get_LiveHosts import get_subdomain

# hosts = get_subdomain('mcdonalds.com')

def get_js(hosts): 
    # print("[*] Starting js files enumeration...")

    hosts_input = '\n'.join(hosts)
    katana = subprocess.Popen(['katana' ,'-jc', '-rl', '15', '-rd', '2', '-silent'], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL, stdout=subprocess.PIPE, text=True)
    js_urls = subprocess.Popen(['grep', '-E', r'\.js($|\?|\.)'],stdout=subprocess.PIPE, stdin=katana.stdout, stderr=subprocess.PIPE, text=True)
    
    katana.stdout.close()
    katana.stdin.write(hosts_input)
    katana.stdin.close()
    urls, err = js_urls.communicate()
    
    js_urls = [line.strip() for line in urls.strip().split("\n") if line]
    return js_urls

# print(get_js(hosts))