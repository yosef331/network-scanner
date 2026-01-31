# scanner/cli.py

import argparse
import ipaddress
import socket  # <-- جديد: للحصول على عنوان IP المحلي
from .core import scan_network, save_to_csv, port_scan
from pyfiglet import Figlet
from termcolor import colored

def main():
    # ... (البانر و argparse يبقون كما هم) ...
    f = Figlet(font='slant')
    banner = f.renderText('Net Scanner')
    print(colored(banner, 'cyan'))

    parser = argparse.ArgumentParser(
        description=colored("أداة احترافية لاكتشاف الأجهزة وفحص المنافذ على الشبكة.", 'yellow'),
        epilog=colored("مثال: sudo python3 main.py -t 192.168.1.1/24 --scan-ports --ports 22,80,443", 'yellow'),
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    network_group = parser.add_argument_group('خيارات فحص الشبكة')
    network_group.add_argument("-t", "--target", dest="target_ip", help="حدد نطاق الشبكة المراد فحصه (مثال: 192.168.1.1/24)", required=True)
    network_group.add_argument("-o", "--output", dest="output_file", help="(اختياري) اسم ملف CSV لحفظ النتائج فيه.")

    port_group = parser.add_argument_group('خيارات فحص المنافذ')
    port_group.add_argument("--scan-ports", action="store_true", help="تفعيل ميزة فحص المنافذ على الأجهزة المكتشفة.")
    port_group.add_argument("--ports", dest="ports_to_scan", help="قائمة المنافذ لفحصها، مفصولة بفاصلة (مثال: 21,22,80,443,8080).\nالافتراضي هو أشهر 10 منافذ.", default="21,22,23,25,80,110,139,443,445,3389")

    options = parser.parse_args()

    try:
        ipaddress.ip_network(options.target_ip, strict=False)
    except ValueError:
        print(colored(f"\n[!] خطأ: صيغة الشبكة '{options.target_ip}' غير صالحة.", 'red'))
        print(colored("[!] يرجى استخدام صيغة CIDR، مثال: 192.168.1.1/24", 'red'))
        return

    def print_status(message, color='blue'):
        print(colored(message, color))
    
    scan_result = scan_network(options.target_ip, print_fn=print_status)

    if scan_result is None:
        scan_result = [] # نهيئ قائمة فارغة إذا حدث خطأ صلاحيات لتجنب الأخطاء لاحقاً
    
    # --- التحسين الجديد: إضافة الجهاز المحلي (localhost) إلى قائمة الفحص ---
    if options.scan_ports:
        try:
            # الحصول على عنوان IP المحلي
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            
            # التحقق مما إذا كان الجهاز المحلي موجوداً بالفعل في النتائج
            found = any(client['ip'] == local_ip for client in scan_result)
            if not found:
                print_status(f"[*] إضافة الجهاز المحلي ({local_ip}) إلى قائمة الفحص.", 'cyan')
                # لا نعرف عنوان MAC، لذلك نضع N/A
                scan_result.append({'ip': local_ip, 'mac': 'N/A (Localhost)'})
        except socket.gaierror:
            print_status("[!] لم أتمكن من تحديد عنوان IP المحلي.", 'yellow')
    # --------------------------------------------------------------------

    if not scan_result:
        print(colored("\n[-] لم يتم العثور على أي أجهزة نشطة في هذا النطاق.", 'yellow'))
        return

    if options.scan_ports:
        try:
            ports = [int(p.strip()) for p in options.ports_to_scan.split(',')]
        except ValueError:
            print(colored("\n[!] خطأ: صيغة قائمة المنافذ غير صالحة. تأكد من أنها أرقام مفصولة بفاصلة.", 'red'))
            return

        print_status("\n[*] بدء فحص المنافذ على الأجهزة المكتشفة...", 'cyan')
        port_scan(scan_result, ports, print_fn=print_status)

    # ... (بقية الكود لطباعة الجدول وحفظ الملف يبقى كما هو) ...
    print("\n" + colored("="*60, 'green'))
    print(colored("نتائج الفحص النهائية:", 'green'))
    print(colored("="*60, 'green'))
    print(colored("عنوان IP\t\tعنوان MAC\t\tالمنافذ المفتوحة", 'cyan'))
    print(colored("------------------------------------------------------------", 'cyan'))
    for client in scan_result:
        open_ports_str = ",".join(map(str, client.get('open_ports', []))) or "N/A"
        print(f"{client['ip']:<16}\t{client['mac']:<17}\t{colored(open_ports_str, 'yellow')}")
    print(colored("="*60, 'green'))

    if options.output_file:
        save_to_csv(scan_result, options.output_file, print_fn=print_status)
