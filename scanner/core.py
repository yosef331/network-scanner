# scanner/core.py

import os
import csv
import socket # <-- جديد: مكتبة الاتصالات الأساسية
try:
    from scapy.all import ARP, Ether, srp
except ImportError:
    print("خطأ: مكتبة scapy غير مثبتة.")
    print("يرجى تثبيتها باستخدام الأمر: pip install scapy")
    exit()

# ... دالة scan_network تبقى كما هي ...
def scan_network(target_ip, print_fn):
    if os.geteuid() != 0:
        print_fn("\n[!] خطأ: هذه الأداة تتطلب صلاحيات المدير (root).", 'red')
        print_fn("[!] يرجى تشغيلها باستخدام 'sudo'.", 'red')
        return None
    print_fn(f"[*] جاري فحص الشبكة: {target_ip}", 'blue')
    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=3, verbose=0)[0]
    clients_list = []
    for element in answered_list:
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(client_dict)
    if clients_list:
        print_fn(f"[+] تم العثور على {len(clients_list)} جهاز.", 'green')
    return clients_list


# --- دالة جديدة وقوية: لفحص المنافذ ---
def port_scan(clients, ports, print_fn):
    """
    يفحص قائمة من المنافذ على كل جهاز في قائمة العملاء.
    ويقوم بتحديث قائمة العملاء مباشرة بمعلومات المنافذ المفتوحة.
    """
    for i, client in enumerate(clients):
        ip = client['ip']
        client['open_ports'] = [] # نهيئ قائمة فارغة للمنافذ المفتوحة
        
        # طباعة تقدم العملية
        progress = f"({i+1}/{len(clients)})"
        print_fn(f"    -> جاري فحص المنافذ للجهاز {ip} {progress}", 'blue')

        for port in ports:
            try:
                # 1. إنشاء سوكيت جديد لكل منفذ
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                # 2. تحديد مهلة زمنية قصيرة (مثلاً 0.5 ثانية) لتجنب الانتظار الطويل
                socket.setdefaulttimeout(0.5)
                # 3. محاولة الاتصال بالمنفذ
                result = sock.connect_ex((ip, port))
                # 4. إذا كان الرد 0، فهذا يعني أن المنفذ مفتوح
                if result == 0:
                    client['open_ports'].append(port)
                # 5. إغلاق الاتصال
                sock.close()
            except socket.error as e:
                print_fn(f"    [!] خطأ في الاتصال بـ {ip}:{port} - {e}", 'red')
# ------------------------------------------------

# ... دالة save_to_csv تحتاج لتعديل بسيط لتشمل المنافذ ...
def save_to_csv(clients, filename, print_fn):
    try:
        with open(filename, 'w', newline='') as csvfile:
            # --- تعديل: إضافة حقل المنافذ ---
            fieldnames = ['ip', 'mac', 'open_ports']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for client in clients:
                # تحويل قائمة المنافذ إلى نص قبل الحفظ
                client['open_ports'] = ",".join(map(str, client.get('open_ports', [])))
                writer.writerow(client)
        print_fn(f"\n[+] تم حفظ النتائج بنجاح في الملف: {filename}", 'green')
    except IOError:
        print_fn(f"\n[!] خطأ: لم أتمكن من الكتابة إلى الملف {filename}.", 'red')
