// MVP web de SecureBank. Todo el DOM se arma con textContent y createElement (nunca HTML como texto): sin XSS.
// El JWT vive solo en memoria: no queda guardado en el navegador al alcance de un script inyectado.
"use strict";

let token = null;
const $ = (id) => document.getElementById(id);
const clp = new Intl.NumberFormat("es-CL", { style: "currency", currency: "CLP" });

function avisar(texto, esError = false) {
  const aviso = $("aviso");
  aviso.textContent = texto;
  aviso.className = esError ? "error" : "";
  aviso.hidden = false;
}

async function api(metodo, ruta, cuerpo) {
  const headers = { "Content-Type": "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  const r = await fetch(ruta, { method: metodo, headers, body: cuerpo ? JSON.stringify(cuerpo) : undefined });
  const datos = await r.json().catch(() => ({}));
  if (r.status === 401 && token) {
    salir();
    throw new Error("La sesión expiró, vuelve a iniciar sesión");
  }
  if (!r.ok) throw new Error(datos.error || "Error " + r.status);
  return datos;
}

function fila(celdas, columnaMonto) {
  const tr = document.createElement("tr");
  celdas.forEach((c, i) => {
    const td = document.createElement("td");
    if (c instanceof Node) td.append(c); else td.textContent = c;
    if (i === columnaMonto) td.className = "monto";
    tr.append(td);
  });
  return tr;
}

async function cargarMovimientos(cuenta) {
  const { movements } = await api("GET", "/accounts/" + encodeURIComponent(cuenta) + "/movements");
  $("mov-cuenta").textContent = "· cuenta " + cuenta;
  $("movimientos").replaceChildren(
    ...movements.map((m) => fila([m.created_at, m.origin, m.target, clp.format(m.amount)], 3))
  );
}

async function cargarBanca() {
  const yo = await api("GET", "/users/me");
  const { accounts } = await api("GET", "/accounts");
  $("quien").textContent = yo.nombre;
  $("cuentas").replaceChildren(...accounts.map((a) => {
    const ver = document.createElement("button");
    ver.type = "button";
    ver.textContent = "Ver movimientos";
    ver.addEventListener("click", () => cargarMovimientos(a.id).catch((e) => avisar(e.message, true)));
    return fila([a.id, clp.format(a.balance), ver], 1);
  }));
  $("origen").replaceChildren(...accounts.map((a) => new Option(a.id, a.id)));
  if (accounts.length) await cargarMovimientos(accounts[0].id);
  for (const id of ["quien", "salir", "vista-banca"]) $(id).hidden = false;
  $("vista-login").hidden = true;
}

function salir() {
  token = null;
  for (const id of ["quien", "salir", "vista-banca"]) $(id).hidden = true;
  $("vista-login").hidden = false;
  $("movimientos").replaceChildren();
}

function alEnviar(id, accion) {
  $(id).addEventListener("submit", async (e) => {
    e.preventDefault();
    const form = e.target;
    try {
      await accion(Object.fromEntries(new FormData(form)), form);
    } catch (err) {
      avisar(err.message, true);
    }
  });
}

alEnviar("form-login", async (datos, form) => {
  token = (await api("POST", "/login", datos)).access_token;
  form.reset();
  $("aviso").hidden = true;
  await cargarBanca();
});

alEnviar("form-registro", async (datos, form) => {
  const r = await api("POST", "/users", datos);
  form.reset();
  avisar("Usuario " + r.username + " creado con la cuenta " + r.account + ". Ya puedes iniciar sesión.");
});

alEnviar("form-transferir", async (datos, form) => {
  // El servidor vuelve a validar el monto (AM-03); aquí solo se convierte a entero.
  const r = await api("POST", "/transfer", { ...datos, amount: Number(datos.amount) });
  form.reset();
  avisar("Transferiste " + clp.format(r.amount) + " a la cuenta " + r.targetAccount);
  await cargarBanca();
});

$("salir").addEventListener("click", salir);
