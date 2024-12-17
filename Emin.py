import re
import csv
import json
from collections import defaultdict
from bs4 import BeautifulSoup

# Fayl adlari
log_file = "access_log.txt"
blacklist_html = "thread_feed.html"
url_status_report_file = "url_status_report.txt"
malware_candidates_file = "malware_candidates.csv"
alert_json_file = "alert.json"
summary_json_file = "summary_report.json"

# 1. Log faylindan URL-ləri və status kodlarını çıxaran funksiya
def extract_urls_and_status(log_file):
    url_status_count = defaultdict(int)
    url_status_list = []
    log_pattern = r'\"[A-Z]+ (.*?) HTTP.*?\" (\d{3})'
    
    with open(log_file, "r") as file:
        for line in file:
            match = re.search(log_pattern, line)
            if match:
                url, status = match.groups()
                url_status_list.append((url, status))
                if status == "404":
                    url_status_count[url] += 1
    return url_status_list, url_status_count

# 2. URL-ləri status kodu ilə txt faylına yazmaq
def save_url_status_to_txt(url_status_list, output_file):
    with open(output_file, "w") as file:
        for url, status in url_status_list:
            file.write(f"{url} {status}\n")

# 3. 404 statuslu URL-ləri CSV faylına yazmaq
def save_404_to_csv(url_status_count, output_file):
    with open(output_file, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "404 Count"])
        for url, count in url_status_count.items():
            writer.writerow([url, count])

# 4. Qara siyahi domenlərini HTML faylından çıxarmaq
def extract_blacklist_domains(html_file):
    blacklist_domains = set()
    with open(html_file, "r") as file:
        soup = BeautifulSoup(file, "html.parser")
        for link in soup.find_all("a"):
            domain = link.text.strip()
            if domain:
                blacklist_domains.add(domain)
    return blacklist_domains

# 5. URL-ləri qara siyahi ilə yoxlamaq
def check_urls_against_blacklist(url_status_list, blacklist_domains):
    alert_urls = []
    for url, status in url_status_list:
        for domain in blacklist_domains:
            if domain in url:
                alert_urls.append({"url": url, "status": status, "blacklist_domain": domain})
    return alert_urls

# 6. JSON faylları yaratmaq
def save_to_json(data, output_file):
    with open(output_file, "w") as file:
        json.dump(data, file, indent=4)

# 7. Xülasə hesabatı yaratmaq
def create_summary_report(url_status_count, alert_urls):
    total_requests = sum(url_status_count.values())
    total_404 = len(url_status_count)
    total_alerts = len(alert_urls)
    summary = {
        "total_requests": total_requests,
        "total_404_urls": total_404,
        "total_alerts": total_alerts,
    }
    return summary

# Main funksiya
def main():
    # 1. Log faylından URL və status kodları çıxarmaq
    url_status_list, url_status_count = extract_urls_and_status(log_file)
    
    # 2. URL-ləri status kodu ilə TXT faylına yazmaq
    save_url_status_to_txt(url_status_list, url_status_report_file)
    
    # 3. 404 statuslu URL-ləri CSV faylına yazmaq
    save_404_to_csv(url_status_count, malware_candidates_file)
    
    # 4. Qara siyahi domenlərini çıxarmaq
    blacklist_domains = extract_blacklist_domains(blacklist_html)
    
    # 5. URL-ləri qara siyahi ilə yoxlamaq
    alert_urls = check_urls_against_blacklist(url_status_list, blacklist_domains)
    save_to_json(alert_urls, alert_json_file)
    
    # 6. Xülasə hesabatı yaratmaq
    summary = create_summary_report(url_status_count, alert_urls)
    save_to_json(summary, summary_json_file)
    
    print("Tapşırıq tamamlandı: Bütün fayllar yaradıldı.")

if __name__ == "__main__":
    main()
