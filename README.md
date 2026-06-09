
# 👻 GhostPreload

**GhostPreload** adalah utility berbasis `LD_PRELOAD` yang dirancang untuk kebutuhan *security research* dan *pentesting* dalam mensimulasikan teknik userland rootkit dan library hooking pada sistem operasi Linux.

---

## 📋 Prasyarat Sistem (Prerequisites)

Sebelum melakukan kompilasi dan menggunakan script ini, pastikan sistem kamu sudah menginstal paket-paket kompilator dasar (C/C++ development tools).

### 1. Distro Berbasis Debian / Ubuntu / Linux Mint:
```bash
sudo apt update
sudo apt install build-essential -y

sudo dnf groupinstall "Development Tools" -y
# atau jika menggunakan versi lama:
sudo yum groupinstall "Development Tools" -y
