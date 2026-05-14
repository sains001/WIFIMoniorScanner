# WiFiMonitorScanner

WiFiMonitorScanner adalah tool Python untuk mendeteksi jaringan Wi-Fi di sekitar memakai interface monitor mode. Tool ini membaca frame beacon dan probe response secara pasif, lalu menampilkan SSID, BSSID, channel, security, RSSI, dan jumlah frame yang terlihat.

Gunakan hanya untuk audit jaringan milik sendiri atau lingkungan yang Anda punya izin untuk uji.

## Fitur

- Deteksi jaringan Wi-Fi sekitar dari monitor mode
- Menampilkan SSID dan BSSID
- Deteksi channel dan frekuensi jika tersedia
- Deteksi security dasar: open, WEP/unknown, WPA, WPA2/RSN, WPS
- Menampilkan RSSI/sinyal jika driver menyediakan informasi RadioTap
- Channel hopping otomatis
- Output live table
- Simpan hasil ke JSON atau CSV
- Pasif: tidak mengirim deauth, tidak cracking, dan tidak mengambil isi trafik pengguna

## Kebutuhan

- Linux
- Python 3
- Adapter Wi-Fi yang mendukung monitor mode
- Root/sudo untuk sniffing
- Scapy
- `iw` untuk channel hopping

Install Scapy jika belum ada:

```bash
python3 -m pip install scapy
```

## Struktur

```text
WiFiMonitorScanner/
├── wifi_monitor_scanner.py
└── README.md
```

## Mengaktifkan Monitor Mode

Cek nama interface:

```bash
iw dev
```

Contoh memakai `airmon-ng`:

```bash
sudo airmon-ng start wlan0
```

Biasanya interface monitor menjadi:

```text
wlan0mon
```

Alternatif memakai `ip` dan `iw`:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

Setelah selesai, kembalikan ke managed mode:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type managed
sudo ip link set wlan0 up
```

## Cara Menjalankan

Masuk ke folder tool:

```bash
cd /home/kali/WiFiMonitorScanner
```

Scan dasar selama 30 detik:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon
```

Scan selama 60 detik:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon -t 60
```

## Contoh Penggunaan

Scan channel 1, 6, dan 11:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon --channels 1,6,11
```

Scan channel 1 sampai 13:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon --channels 1-13
```

Matikan channel hopping:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon --no-hop
```

Atur dwell time per channel:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon --dwell 1.5
```

Simpan hasil ke JSON:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon -t 60 --json hasil.json
```

Simpan hasil ke CSV:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon -t 60 --csv hasil.csv
```

Mode quiet:

```bash
sudo python3 wifi_monitor_scanner.py -i wlan0mon -t 60 --quiet --csv hasil.csv
```

## Opsi

| Opsi | Default | Keterangan |
| --- | --- | --- |
| `-i`, `--interface` | wajib | Interface monitor mode, contoh `wlan0mon` |
| `-t`, `--time` | `30` | Durasi scan dalam detik |
| `--no-hop` | mati | Jangan lakukan channel hopping |
| `--channels` | channel umum 2.4/5 GHz | Daftar channel, contoh `1,6,11` atau `1-13` |
| `--dwell` | `0.75` | Lama berada di setiap channel saat hopping |
| `--refresh` | `1.0` | Interval refresh tampilan live |
| `--json` | kosong | Simpan hasil akhir ke file JSON |
| `--csv` | kosong | Simpan hasil akhir ke file CSV |
| `--quiet` | mati | Jangan tampilkan tabel live |

## Contoh Output

```text
WiFi Monitor Scanner - jaringan ditemukan: 4
Tekan Ctrl+C untuk berhenti.

 RSSI   CH  SECURITY          BSSID              SSID
------------------------------------------------------------------------------
  -42    6  WPA2/RSN          aa:bb:cc:11:22:33  Rumah-5G
  -57   11  WPA2/RSN+WPS      dd:ee:ff:44:55:66  OfficeNet
  -70    1  open              12:34:56:78:90:ab  Guest-WiFi
    ?   36  WPA2/RSN          98:76:54:32:10:ff  <hidden>
```

## Field Output

JSON dan CSV berisi field:

- `ssid`
- `bssid`
- `channel`
- `frequency`
- `security`
- `signal_dbm`
- `vendor`
- `first_seen`
- `last_seen`
- `frames`

Kolom `vendor` saat ini berisi prefix OUI dari MAC address, bukan nama vendor penuh.

## Troubleshooting

Scapy belum ada:

```text
Error: Scapy belum tersedia. Install dengan: python3 -m pip install scapy
```

Tidak dijalankan sebagai root:

```text
Error: butuh root/capability untuk sniffing. Jalankan dengan sudo.
```

Interface salah atau belum monitor mode:

```text
Error interface: ...
```

Solusi:

- Pastikan adapter mendukung monitor mode
- Pastikan interface benar, contoh `wlan0mon`
- Jalankan dengan `sudo`
- Matikan network manager sementara jika mengganggu monitor mode

## Catatan Keamanan

Tool ini hanya mendeteksi jaringan yang memancarkan beacon atau probe response. Hidden SSID bisa tampil sebagai `<hidden>` sampai ada frame yang mengungkap nama jaringan. Hasil RSSI bergantung pada driver dan adapter Wi-Fi yang digunakan.
