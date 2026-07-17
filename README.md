# Docker Container Monitoring System

GPU sunucularında çalışan Docker container'larının auditd ile izlenmesi,
merkezi bir sunucuda toplanması ve web arayüzünden görüntülenmesi için geliştirilmiş
bir altyapı izleme projesi.

## Mimari

- **GPU Server'lar**: auditd ile docker komutlarını izler, agent aracılığıyla
  merkezi sunucuya iletir.
- **Monitoring Server**: FastAPI backend, PostgreSQL veritabanı, React frontend.

## Kurulum

1. `.env.example` dosyasını `.env` olarak kopyalayın ve kendi değerlerinizi girin:
```bash
   cp .env.example .env
```
2. Docker Compose ile başlatın:
```bash
   docker-compose up -d --build
```

## Özellikler

- Audit log tabanlı komut izleme
- Container yaşam döngüsü takibi
- CPU/RAM kaynak kullanımı (host + container bazlı)
- Yetkisiz container erişimi tespiti
- Filtrelenebilir log arayüzü

## Lisans

MIT
