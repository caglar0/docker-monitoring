

@app.on_event("startup")
def run_test_on_startup():
    print("\n" + "🚀 " * 15)
    print("FASTAPI BAŞLADI - PARSER TESTİ ÇALIŞIYOR:")
    test_satiri = 'type=SYSCALL msg=audit(1782881452.123:4567): arch=c000003e syscall=59 success=yes exit=0 ppid=1\
024 pid=5678 auid=1000 uid=0 gid=0 euid=0 comm="dockerd" exe="/usr/bin/dockerd" key="docker"'
    test_sonucu = parse_log(test_satiri)
    print("TEST EDİLEN SATIR:", test_satiri)
    print("PARS EDİLMİŞ ÇIKTI:", test_sonucu)
    print("🚀 " * 15 + "\n")

