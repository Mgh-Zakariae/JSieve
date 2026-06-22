import subprocess

def get_subdomain(domain):
    # print(f"[*] Starting subdomain enumeration for {domain}...")
    subfinder = subprocess.Popen(['subfinder', '-d', domain, '-silent'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    httpx = subprocess.Popen(['httpx-toolkit', '-silent'], stdin=subfinder.stdout, stdout=subprocess.PIPE, text=True)
    
    subfinder.stdout.close()
    live_hosts, err = httpx.communicate()
    
    return [host.split()[0] for host in live_hosts.strip().split('\n')] 
 
