"use strict";

const form = document.getElementById("form-entrar");
const mensaje = document.getElementById("mensaje");
const boton = document.getElementById("boton");

function avisar(texto, clase) {
  mensaje.textContent = texto; // textContent: el texto puede venir del servidor
  mensaje.className = `mensaje ${clase || ""}`;
}

// Si el servidor aun no tiene cuentas, no tiene sentido dejar probar.
fetch("/api/quien")
  .then((r) => r.json())
  .then((d) => {
    if (d.sin_cuentas) {
      avisar(d.aviso, "error");
      boton.disabled = true;
    } else if (d.autenticado) {
      location.href = "/";
    }
  })
  .catch(() => {});

form.addEventListener("submit", async (ev) => {
  ev.preventDefault();
  boton.disabled = true;
  avisar("Comprobando…");

  try {
    const resp = await fetch("/api/entrar", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        usuario: document.getElementById("usuario").value,
        contrasena: document.getElementById("contrasena").value,
      }),
    });
    const datos = await resp.json();
    if (!resp.ok) {
      avisar(datos.error || "No se pudo entrar", "error");
      boton.disabled = false;
      return;
    }
    location.href = "/";
  } catch (err) {
    avisar(err.message, "error");
    boton.disabled = false;
  }
});
