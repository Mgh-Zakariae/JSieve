import os, requests, re, hashlib
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed


def build_sourcemap_candidates(js) : 
    MAP_REGEX = re.compile(r"sourceMappingURL=([^\s\"'*]+)")
    candidates = []
    with open(js['path'], "r", encoding="utf-8") as f:
        content = f.read()  

        match = MAP_REGEX.search(content)
        if match:
            map_name = match.group(1).strip()
            url = urljoin(js['url'], map_name)
            candidates.append({
                'name': map_name,
                'url': url
            })
            
    fallback_url = js["url"] + ".map"
    if not any(c["url"] == fallback_url for c in candidates):
        candidates.append({
                'name': js['filename'] + ".map",
                'url': fallback_url
            })    
    return candidates


def one_map_downloader(url, file_path, file_name):
    if os.path.exists(file_path):
        return {
            "url": url,
            "path": file_path,
            "filename": file_name
        }
    
    if not os.path.exists(file_path):
        try:
            req = requests.get(url, timeout=15)
            if req.status_code == 200:
                with open(file_path, 'w', encoding='utf-8') as file:
                    file.write(req.text)
                print(f"[+] Source map found: {url}")
                return {
                    "url": url,
                    "path": file_path,
                    "filename": file_name
                }
            else: 
                return None
        except Exception as e:
            return None

def map_downloader(candidates, domain, threads=15):
    DIR = f"/tmp/js_files_{domain}"
    found_maps = []

    if not os.path.exists(DIR):
        return 
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = []
        for item in candidates:
            url_hash = hashlib.sha256(item["url"].encode()).hexdigest()[:8]
            file_name = item["url"].split('/')[-1]
            file_path = os.path.join(DIR, f"{url_hash}_{file_name}")
            futures.append(executor.submit(one_map_downloader, item["url"], file_path, file_name))
            
        for future in as_completed(futures):
            result = future.result()
            if result:
                found_maps.append(result)
                print(f"[+] Downloaded: {result['url']}") 
                
    return found_maps  
   
 

 
# urls = ['https://aminecraftmovie.mcdonalds.com/_nuxt/DlAUqK2U.js', 'https://aminecraftmovie.mcdonalds.com/_nuxt/i2rz4DOx.js', 'https://aminecraftmovie.mcdonalds.com/_nuxt/CrELBZ2i.js']
 
# JS = install_js(urls, 'mcdonalds.com')[0]

# print(map_downloader(build_sourcemap_candidates(JS),'mcdonalds.com'))  