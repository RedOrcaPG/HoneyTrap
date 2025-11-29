# 🛡️ IDS_Scanner: Sistem Deteksi Intrusi Sederhana

IDS_Scanner adalah sebuah alat dasar untuk deteksi intrusi jaringan yang memanfaatkan kemampuan pemrosesan paket mentah (raw packet processing) di lingkungan Linux.

Alat ini dirancang untuk mendengarkan lalu lintas jaringan dan menganalisis paket berdasarkan aturan sederhana.

---

## 💻 Prasyarat dan Lingkungan

Proyek ini **wajib** dijalankan dalam **Lingkungan Virtual (VENV)** di sistem operasi **Linux** (seperti Ubuntu atau distro berbasis Debian lainnya), karena ketergantungan utamanya ($\text{netfilterqueue}$) berinteraksi langsung dengan *kernel* Linux.

### ⚠️ Wajib di Ubuntu

Pastikan Anda berada di lingkungan Ubuntu (seperti WSL 2 di Windows atau Virtual Machine), karena modul **netfilterqueue TIDAK DIDUKUNG di Windows atau macOS.**

## 📦 Instalasi Dependensi

IDS_Scanner memerlukan dua modul Python utama: **Scapy** dan **NetfilterQueue**. Kedua modul ini memiliki ketergantungan sistem operasi (OS) yang harus diinstal terlebih dahulu.

### Langkah 1: Instal Dependensi Sistem (Linux)

Sebelum menginstal paket Python, instal *development libraries* yang diperlukan untuk kompilasi:

sudo apt update
sudo apt install build-essential libnetfilter-queue-dev libffi-dev -y

### 🐍 Menggunakan Virtual Environment (VENV)

Sangat disarankan untuk menjalankan *script* ini di dalam $\text{VENV}$ untuk mengisolasi *dependency* dari instalasi Python sistem Anda.
```bash

1.  **Buat VENV:**
    ```bash
    python3 -m venv venv
    ```

2.  **Aktifkan VENV:**
    ```bash
    source venv/bin/activate
    ```
    (Anda akan melihat `(venv)` muncul di *prompt* terminal Anda, menandakan $\text{VENV}$ aktif.)
