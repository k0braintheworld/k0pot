# Servicios systemd

Unidades de **usuario**: no necesitan root, que en este servidor no tenemos
sin contrasena. Con `loginctl enable-linger` arrancan al encender la maquina
aunque nadie inicie sesion.

    loginctl enable-linger $USER
    mkdir -p ~/.config/systemd/user
    cp deploy/*.service ~/.config/systemd/user/
    systemctl --user daemon-reload
    systemctl --user enable --now k0pot-collector k0pot-panel

Operacion:

    systemctl --user status k0pot-collector k0pot-panel
    journalctl --user -u k0pot-panel -f
    systemctl --user restart k0pot-panel

Cowrie no necesita unidad: el `restart: unless-stopped` del compose ya lo
levanta con Docker.

Nota: `StartLimitIntervalSec` y `StartLimitBurst` van en `[Unit]`. Puestas en
`[Service]` systemd las ignora con un aviso y el freno anti-bucle no existe.
