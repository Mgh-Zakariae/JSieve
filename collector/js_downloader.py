import requests, os, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

def download_one_js(js_url, file_path, file_name):
    try :
        if not os.path.exists(file_path):
            req = requests.get(url=js_url, timeout=10) 
            if req.status_code == 200:
                
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(req.text)
                    return {
                        'url': js_url,
                        'path': file_path,
                        'filename': file_name
                    }
            else:
                return None
        else:
            return {
                'url': js_url,
                'path': file_path,
                'filename': file_name
            }
    except Exception as e :
            # print(f"[-] Failed to download {url}: {e}")    
        return None
        
def install_js(js_urls, domain, threads=15):
    DIR = f"/tmp/js_files_{domain}"
    downloaded = []
    
    if not os.path.exists(DIR):
            os.mkdir(DIR)
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for js_url in js_urls:
            url_hash = hashlib.sha256(js_url.encode()).hexdigest()[:8]
            file_name = js_url.split('/')[-1]
            file_path = os.path.join(DIR, f"{url_hash}_{file_name}")
            futures.append(executor.submit(download_one_js, js_url, file_path, file_name))
        for future in as_completed(futures):
            result = future.result()
            if result:
                downloaded.append(result)
                # print(f"[+] Downloaded: {result['url']}") 
    return downloaded       
        
    
# urls = ['https://aminecraftmovie.mcdonalds.com/_nuxt/DlAUqK2U.js', 'https://aminecraftmovie.mcdonalds.com/_nuxt/i2rz4DOx.js', 'https://aminecraftmovie.mcdonalds.com/_nuxt/CrELBZ2i.js']

# print(install_js(urls, 'mcdonalds.com'))