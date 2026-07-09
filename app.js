"use strict";
/* App del sitio: descifra datos.json en el navegador y renderiza las secciones.
   La app es estática y estable; lo único que cambia entre corridas es datos.json
   (blob AES-256-GCM) y meta.json (timestamp para detectar versiones nuevas). */

let CFG = null;                     // {salt, iv, iter, generado} desde datos.json
let BLOB = null;                    // ciphertext base64 desde datos.json
let D = null;                       // payload descifrado
let vista = "resumen";
let rango = 365;                    // días visibles (null = todo)
let simboloSel = null, modoSerie = "a", modoPrecios = "c";

/* ---------- utilidades ---------- */
const $ = s => document.querySelector(s);
const b64a = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ab64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const diaAFecha = d => new Date(d * 86400000);
const isoDia = d => diaAFecha(d).toISOString().slice(0,10);
const fmtFecha = d => diaAFecha(d).toLocaleDateString("es-AR",{day:"2-digit",month:"short",year:"2-digit",timeZone:"UTC"});
const fmtNum = (v,dec) => v.toLocaleString("es-AR",{minimumFractionDigits:dec??(v<100?2:0),maximumFractionDigits:dec??(v<100?2:0)});
const fmtPct = v => (v>0?"+":"") + v.toLocaleString("es-AR",{minimumFractionDigits:1,maximumFractionDigits:1}) + "%";
function el(tag, attrs, texto){ const e=document.createElement(tag);
  for(const k in attrs||{}) e.setAttribute(k,attrs[k]);
  if(texto!=null) e.textContent=texto; return e; }

/* ---------- datos cifrados (datos.json) ---------- */
const datosListos = (async () => {
  const r = await fetch("datos.json", {cache:"no-store"});
  if(!r.ok) throw new Error("datos.json: HTTP " + r.status);
  const j = await r.json();
  CFG = {salt:j.salt, iv:j.iv, iter:j.iter, generado:j.generado};
  BLOB = j.blob;
})();
datosListos.catch(() => {
  $("#loginError").textContent =
    "No se pudieron cargar los datos. La página necesita servirse por http (no file://).";
});

/* ---------- login / cifrado ---------- */
async function derivarClave(pass){
  const km = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({name:"PBKDF2", salt:b64a(CFG.salt), iterations:CFG.iter, hash:"SHA-256"},
                                 km, {name:"AES-GCM", length:256}, true, ["decrypt"]);
}
async function descifrarCon(clave){
  const pt = await crypto.subtle.decrypt({name:"AES-GCM", iv:b64a(CFG.iv)}, clave, b64a(BLOB));
  return JSON.parse(new TextDecoder().decode(pt));
}
async function intentarSesionGuardada(){
  const raw = sessionStorage.getItem("clave_sitio");
  if(!raw) return false;
  try{
    await datosListos;
    const clave = await crypto.subtle.importKey("raw", b64a(raw), {name:"AES-GCM"}, true, ["decrypt"]);
    D = await descifrarCon(clave);
    return true;
  }catch(e){ sessionStorage.removeItem("clave_sitio"); return false; }
}
$("#formLogin").addEventListener("submit", async ev => {
  ev.preventDefault();
  const btn = $("#btnEntrar"); btn.disabled = true; btn.textContent = "Verificando…";
  $("#loginError").textContent = "";
  try{
    await datosListos;
  }catch(e){
    $("#loginError").textContent =
      "No se pudieron cargar los datos. La página necesita servirse por http (no file://).";
    btn.disabled = false; btn.textContent = "Ingresar";
    return;
  }
  try{
    const clave = await derivarClave($("#pass").value);
    D = await descifrarCon(clave);
    sessionStorage.setItem("clave_sitio", ab64(await crypto.subtle.exportKey("raw", clave)));
    arrancar();
  }catch(e){
    $("#loginError").textContent = "Contraseña incorrecta.";
    $("#pass").value = ""; $("#pass").focus();
  }
  btn.disabled = false; btn.textContent = "Ingresar";
});
$("#btnSalir").addEventListener("click", () => { sessionStorage.removeItem("clave_sitio"); location.reload(); });

/* ---------- detección de versión nueva ---------- */
function vigilarActualizaciones(){
  setInterval(async () => {
    try{
      const r = await fetch("meta.json?_=" + Date.now(), {cache:"no-store"});
      if(!r.ok) return;
      const m = await r.json();
      if(m.generado && m.generado !== CFG.generado){
        $("#actualizando").classList.remove("oculto");
        setTimeout(() => location.reload(), 2500);
      }
    }catch(e){ /* offline: sin polling */ }
  }, 5 * 60 * 1000);
}

/* ---------- charts (SVG, sin dependencias) ---------- */
function ticksLindos(min, max, n){
  const span = max - min || 1, paso0 = span / n, mag = Math.pow(10, Math.floor(Math.log10(paso0)));
  const paso = [1,2,2.5,5,10].map(m => m*mag).find(p => span/p <= n) || 10*mag;
  const t = []; for(let v = Math.ceil(min/paso)*paso; v <= max + 1e-9; v += paso) t.push(v);
  return t;
}
function lineChart(cont, series, opciones){
  const o = Object.assign({alto:300, fmtY:v=>fmtNum(v)}, opciones);
  cont.textContent = "";
  const ancho = Math.max(cont.clientWidth || 900, 320), alto = o.alto;
  const M = {t:14, r:14, b:26, l:56};
  const xs = series.flatMap(s => s.puntos.map(p => p[0]));
  const ys = series.flatMap(s => s.puntos.map(p => p[1]));
  if(!xs.length){ cont.append(el("div",{style:"color:var(--muted);padding:30px 0;text-align:center"},"Sin datos en el rango")); return; }
  const x0 = Math.min(...xs), x1 = Math.max(...xs);
  let y0 = Math.min(...ys), y1 = Math.max(...ys);
  const margen = (y1 - y0) * 0.06 || y1 * 0.05 || 1; y0 -= margen; y1 += margen;
  const X = d => M.l + (d - x0) / (x1 - x0 || 1) * (ancho - M.l - M.r);
  const Y = v => alto - M.b - (v - y0) / (y1 - y0 || 1) * (alto - M.t - M.b);
  const svg = document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox", `0 0 ${ancho} ${alto}`);
  svg.setAttribute("width","100%");
  const NS = n => document.createElementNS("http://www.w3.org/2000/svg", n);
  for(const t of ticksLindos(y0, y1, 5)){
    const l = NS("line");
    l.setAttribute("x1",M.l); l.setAttribute("x2",ancho-M.r);
    l.setAttribute("y1",Y(t)); l.setAttribute("y2",Y(t));
    l.setAttribute("stroke","var(--grid)"); svg.append(l);
    const tx = NS("text"); tx.setAttribute("x",M.l-8); tx.setAttribute("y",Y(t)+4);
    tx.setAttribute("text-anchor","end"); tx.textContent = o.fmtY(t); svg.append(tx);
  }
  const nX = Math.min(5, Math.max(2, Math.floor(ancho/170)));
  for(let i=0;i<=nX;i++){
    const d = x0 + (x1-x0)*i/nX;
    const tx = NS("text"); tx.setAttribute("x",X(d)); tx.setAttribute("y",alto-8);
    tx.setAttribute("text-anchor", i===0?"start":(i===nX?"end":"middle"));
    tx.textContent = fmtFecha(d); svg.append(tx);
  }
  for(const s of series){
    const traza = s.puntos.map((pt,i)=>(i?"L":"M")+X(pt[0]).toFixed(1)+" "+Y(pt[1]).toFixed(1)).join("");
    if(o.area && s.puntos.length > 1){
      const pri = s.puntos[0], ult = s.puntos[s.puntos.length-1];
      const a = NS("path");
      a.setAttribute("d", traza + "L"+X(ult[0]).toFixed(1)+" "+(alto-M.b)+"L"+X(pri[0]).toFixed(1)+" "+(alto-M.b)+"Z");
      a.setAttribute("fill", s.color); a.setAttribute("fill-opacity","0.08"); svg.append(a);
    }
    const p = NS("path");
    p.setAttribute("d", traza);
    p.setAttribute("fill","none"); p.setAttribute("stroke",s.color);
    p.setAttribute("stroke-width","2"); p.setAttribute("stroke-linecap","round");
    p.setAttribute("stroke-linejoin","round"); svg.append(p);
    const u = s.puntos[s.puntos.length-1];
    const fin = NS("circle");
    fin.setAttribute("cx",X(u[0]).toFixed(1)); fin.setAttribute("cy",Y(u[1]).toFixed(1));
    fin.setAttribute("r","4"); fin.setAttribute("fill",s.color);
    fin.setAttribute("stroke","var(--surface)"); fin.setAttribute("stroke-width","2");
    svg.append(fin);
  }
  if(series.length > 1){
    const etiquetas = series.map(s => { const u = s.puntos[s.puntos.length-1];
      return {s, y: Y(u[1]) - 9, x: X(u[0]) - 9}; }).sort((a,b) => a.y - b.y);
    for(let i=1;i<etiquetas.length;i++)
      if(etiquetas[i].y - etiquetas[i-1].y < 13) etiquetas[i].y = etiquetas[i-1].y + 13;
    for(const e of etiquetas){
      const tx = NS("text"); tx.setAttribute("x",e.x); tx.setAttribute("y",e.y);
      tx.setAttribute("text-anchor","end"); tx.setAttribute("style",`fill:${e.s.color};font-weight:600`);
      tx.textContent = e.s.nombre; svg.append(tx);
    }
  }
  const cross = NS("line"); cross.setAttribute("y1",M.t); cross.setAttribute("y2",alto-M.b);
  cross.setAttribute("stroke","var(--eje)"); cross.setAttribute("stroke-dasharray","3 3");
  cross.style.display = "none"; svg.append(cross);
  const puntosCross = series.map(s => { const c = NS("circle"); c.setAttribute("r",4);
    c.setAttribute("fill",s.color); c.setAttribute("stroke","var(--surface)");
    c.setAttribute("stroke-width",2); c.style.display="none"; svg.append(c); return c; });
  const tip = el("div",{class:"tooltip oculto"});
  cont.style.position = "relative"; cont.append(svg, tip);
  const xsBase = series[0].puntos.map(p => p[0]);
  svg.addEventListener("pointermove", ev => {
    const r = svg.getBoundingClientRect();
    const dx = x0 + ((ev.clientX - r.left) * (ancho / r.width) - M.l) / (ancho - M.l - M.r) * (x1 - x0);
    let mejor = 0, dist = Infinity;
    for(let i=0;i<xsBase.length;i++){ const dd = Math.abs(xsBase[i]-dx); if(dd<dist){dist=dd;mejor=i;} }
    const dia = xsBase[mejor];
    cross.setAttribute("x1",X(dia)); cross.setAttribute("x2",X(dia)); cross.style.display="";
    tip.textContent = ""; tip.classList.remove("oculto");
    tip.append(el("div",{class:"tfecha"}, diaAFecha(dia).toLocaleDateString("es-AR",{day:"2-digit",month:"long",year:"numeric",timeZone:"UTC"})));
    series.forEach((s,i) => {
      const pt = s.puntos.find(p => p[0]===dia) || s.puntos[Math.min(mejor, s.puntos.length-1)];
      if(!pt){ puntosCross[i].style.display="none"; return; }
      puntosCross[i].setAttribute("cx",X(pt[0])); puntosCross[i].setAttribute("cy",Y(pt[1]));
      puntosCross[i].style.display="";
      const fila = el("div",{class:"fila"});
      const clave = el("span",{class:"clave"}); clave.style.borderTopColor = s.color;
      fila.append(clave, el("span",{}, s.nombre), el("span",{class:"tv"}, o.fmtY(pt[1])));
      tip.append(fila);
    });
    const tw = tip.offsetWidth, px = (X(dia)/ancho)*r.width;
    tip.style.left = Math.min(Math.max(px+14, 4), r.width - tw - 4) + "px";
    tip.style.top = "10px";
  });
  svg.addEventListener("pointerleave", () => { cross.style.display="none";
    puntosCross.forEach(c=>c.style.display="none"); tip.classList.add("oculto"); });
}
function sparkline(td, valores){
  const w=110, h=26; if(valores.length<2){ td.textContent="–"; return; }
  const min=Math.min(...valores), max=Math.max(...valores);
  const X=i=>i/(valores.length-1)*(w-4)+2, Y=v=>h-3-((v-min)/(max-min||1))*(h-6);
  const svg=document.createElementNS("http://www.w3.org/2000/svg","svg");
  svg.setAttribute("viewBox",`0 0 ${w} ${h}`); svg.setAttribute("width",w); svg.setAttribute("height",h);
  const p=document.createElementNS("http://www.w3.org/2000/svg","path");
  p.setAttribute("d",valores.map((v,i)=>(i?"L":"M")+X(i).toFixed(1)+" "+Y(v).toFixed(1)).join(""));
  p.setAttribute("fill","none"); p.setAttribute("stroke","var(--s1)");
  p.setAttribute("stroke-width","1.6"); p.setAttribute("stroke-linecap","round");
  svg.append(p); td.textContent=""; td.append(svg);
}

/* ---------- Excel (.xlsx real: zip sin compresión + SpreadsheetML mínimo) ---------- */
const _crcTabla = (() => { const t = new Uint32Array(256);
  for(let n=0;n<256;n++){ let c=n; for(let k=0;k<8;k++) c = (c&1) ? 0xEDB88320 ^ (c>>>1) : c>>>1; t[n]=c; }
  return t; })();
function crc32(u8){ let c = 0xFFFFFFFF;
  for(let i=0;i<u8.length;i++) c = _crcTabla[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0; }
function zipStore(entradas){  // entradas: [{nombre, datos:Uint8Array}] -> Uint8Array (método store)
  const enc = new TextEncoder(); const partes = [], centro = []; let offset = 0;
  const u16 = v => new Uint8Array([v&255, (v>>8)&255]);
  const u32 = v => new Uint8Array([v&255, (v>>8)&255, (v>>16)&255, (v>>>24)&255]);
  for(const e of entradas){
    const nombre = enc.encode(e.nombre), crc = crc32(e.datos), n = e.datos.length;
    partes.push(u32(0x04034b50), u16(20), u16(0), u16(0), u16(0), u16(0),
                u32(crc), u32(n), u32(n), u16(nombre.length), u16(0), nombre, e.datos);
    centro.push({nombre, crc, n, offset});
    offset += 30 + nombre.length + n;
  }
  const inicioCentro = offset; let tamCentro = 0;
  for(const c of centro){
    partes.push(u32(0x02014b50), u16(20), u16(20), u16(0), u16(0), u16(0), u16(0),
                u32(c.crc), u32(c.n), u32(c.n), u16(c.nombre.length), u16(0), u16(0),
                u16(0), u16(0), u32(0), u32(c.offset), c.nombre);
    tamCentro += 46 + c.nombre.length;
  }
  partes.push(u32(0x06054b50), u16(0), u16(0), u16(centro.length), u16(centro.length),
              u32(tamCentro), u32(inicioCentro), u16(0));
  let total = 0; for(const p of partes) total += p.length;
  const out = new Uint8Array(total); let pos = 0;
  for(const p of partes){ out.set(p, pos); pos += p.length; }
  return out;
}
const xmlEsc = s => String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
function xlsx(encabezados, filas, nombreHoja){  // filas: arrays de string|number|null
  const fila = (celdas, r) => "<row r=\"" + r + "\">" + celdas.map((v,i) => {
    if(v==null || v==="") return "";
    const col = colLetra(i) + r;
    if(typeof v === "number") return `<c r="${col}"><v>${v}</v></c>`;
    return `<c r="${col}" t="inlineStr"><is><t>${xmlEsc(v)}</t></is></c>`;
  }).join("") + "</row>";
  function colLetra(i){ let s=""; i++; while(i){ const m=(i-1)%26; s=String.fromCharCode(65+m)+s; i=(i-m-1)/26; } return s; }
  const hoja = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`
    + fila(encabezados, 1) + filas.map((f,i) => fila(f, i+2)).join("") + `</sheetData></worksheet>`;
  const wb = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="${xmlEsc(nombreHoja)}" sheetId="1" r:id="rId1"/></sheets></workbook>`;
  const rels = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`;
  const rels0 = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`;
  const tipos = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`;
  const enc = new TextEncoder();
  return zipStore([
    {nombre:"[Content_Types].xml", datos:enc.encode(tipos)},
    {nombre:"_rels/.rels", datos:enc.encode(rels0)},
    {nombre:"xl/workbook.xml", datos:enc.encode(wb)},
    {nombre:"xl/_rels/workbook.xml.rels", datos:enc.encode(rels)},
    {nombre:"xl/worksheets/sheet1.xml", datos:enc.encode(hoja)},
  ]);
}
function descargarXlsx(){
  const {encabezados, filas} = matrizPrecios();
  const bytes = xlsx(encabezados, filas, "Precios");
  const blob = new Blob([bytes], {type:"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"});
  const a = el("a", {href: URL.createObjectURL(blob),
                     download: "precios_" + CFG.generado.slice(0,10).replaceAll("-","") + ".xlsx"});
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
}

/* ---------- datos derivados ---------- */
function corte(dias){ if(rango==null) return -Infinity; return dias[dias.length-1] - rango; }
function serieVisible(sim){
  const vals = modoSerie==="a" ? sim.a : sim.c, c = corte(sim.d), pts = [];
  for(let i=0;i<sim.d.length;i++) if(sim.d[i] >= c) pts.push([sim.d[i], vals[i]]);
  return pts;
}
function variacion(vals, n){
  if(vals.length < n+1) return null;
  const a = vals[vals.length-1-n], b = vals[vals.length-1];
  return a > 0 ? (b/a - 1) * 100 : null;
}
function matrizPrecios(){  // fecha (desc) × símbolo, respetando rango y modoPrecios
  const dias = new Set();
  for(const s of D.simbolos){ const c = corte(s.d); for(const d of s.d) if(d >= c) dias.add(d); }
  const orden = [...dias].sort((a,b) => b-a);
  const mapas = D.simbolos.map(s => { const m = new Map();
    const vals = modoPrecios==="a" ? s.a : s.c;
    s.d.forEach((d,i) => m.set(d, vals[i])); return m; });
  const encabezados = ["Fecha", ...D.simbolos.map(s => s.s)];
  const filas = orden.map(d => [isoDia(d), ...mapas.map(m => m.has(d) ? m.get(d) : null)]);
  return {encabezados, filas};
}

/* ---------- render por sección ---------- */
function renderRangos(){
  document.querySelectorAll("[data-rango]").forEach(cont => {
    cont.textContent = "";
    cont.append(el("span",{class:"rot"},"Rango:"));
    for(const [rot, dias] of [["1M",31],["6M",183],["1A",365],["5A",1827],["Todo",null]]){
      const b = el("button",{}, rot);
      if(dias===rango) b.classList.add("activo");
      b.addEventListener("click", () => { rango = dias; renderRangos(); renderVista(); });
      cont.append(b);
    }
  });
}
function renderTiles(){
  const t = $("#tiles"); t.textContent = "";
  for(const [par, s] of Object.entries(D.mep)){
    const tile = el("div",{class:"tile"});
    tile.append(el("div",{class:"rotulo"}, "MEP " + par));
    tile.append(el("div",{class:"valor"}, "$ " + fmtNum(s.v[s.v.length-1], 0)));
    const v = variacion(s.v, 1);
    if(v!=null){ tile.append(el("div",{class:"delta "+(v>=0?"up":"down")},
        (v>=0?"▲ ":"▼ ")+fmtPct(v)+" vs rueda anterior")); }
    const chispa = el("div",{class:"chispa"});
    sparkline(chispa, s.v.slice(-30));
    tile.append(chispa);
    t.append(tile);
  }
  const ult = D.salud[0];
  if(ult){
    const tile = el("div",{class:"tile"});
    tile.append(el("div",{class:"rotulo"},"Última corrida ("+ult.p+")"));
    const v = el("div",{class:"valor"}); v.append(el("span",{class:"badge "+ult.r}, ult.r)); tile.append(v);
    tile.append(el("div",{class:"delta"},(ult.va??0)+" válidas · "+(ult.in??0)+" sospechosas"));
    t.append(tile);
  }
  const tile = el("div",{class:"tile"});
  tile.append(el("div",{class:"rotulo"},"Universo"));
  tile.append(el("div",{class:"valor"}, String(D.simbolos.length)));
  tile.append(el("div",{class:"delta"},"instrumentos seguidos"));
  t.append(tile);
}
function renderPrincipal(){
  const sim = D.simbolos.find(s => s.s === simboloSel) || D.simbolos[0];
  simboloSel = sim.s;
  $("#tituloSerie").textContent = sim.s + " — cierre " + (modoSerie==="a"?"ajustado":"crudo") + " (" + sim.m + ")";
  const cob = Math.round(100 * sim.va.reduce((a,b)=>a+b,0) / sim.va.length);
  $("#subSerie").textContent = sim.t + " · " + sim.d.length + " ruedas · " + cob + "% con dato válido";
  lineChart($("#chartPrincipal"), [{nombre:sim.s, color:"var(--s1)", puntos:serieVisible(sim)}],
            {fmtY:v=>fmtNum(v), area:true});
  document.querySelectorAll("#tablaInstrumentos tbody tr").forEach(tr =>
    tr.classList.toggle("sel", tr.dataset.s === sim.s));
}
function renderPrecios(){
  const {encabezados, filas} = matrizPrecios();
  const MAX = 250;
  const thead = $("#tablaPrecios thead"); thead.textContent = "";
  const trh = el("tr"); encabezados.forEach(h => trh.append(el("th",{},h))); thead.append(trh);
  const tbody = $("#tablaPrecios tbody"); tbody.textContent = "";
  for(const f of filas.slice(0, MAX)){
    const tr = el("tr");
    tr.append(el("td",{}, f[0]));
    for(let i=1;i<f.length;i++)
      tr.append(el("td",{}, f[i]==null ? "–" : fmtNum(f[i])));
    tbody.append(tr);
  }
  $("#subPrecios").textContent = "Cierre " + (modoPrecios==="a"?"ajustado":"crudo") +
      " · " + filas.length + " ruedas × " + D.simbolos.length + " símbolos en el rango elegido";
  $("#notaPrecios").textContent = filas.length > MAX
      ? "Se muestran las últimas " + MAX + " ruedas; la descarga a Excel incluye las " + filas.length + " del rango."
      : "La descarga a Excel incluye exactamente lo que ves.";
}
function renderMep(){
  const colores = ["var(--s1)","var(--s2)"];
  const series = Object.entries(D.mep).map(([par,s],i) => {
    const c = corte(s.d), pts = [];
    for(let j=0;j<s.d.length;j++) if(s.d[j]>=c) pts.push([s.d[j], s.v[j]]);
    return {nombre:par, color:colores[i%2], puntos:pts};
  }).filter(s => s.puntos.length);
  lineChart($("#chartMep"), series, {alto:280, fmtY:v=>"$ "+fmtNum(v,0)});
  const leg = $("#legMep"); leg.textContent = "";
  series.forEach(s => { const it = el("span");
    const k = el("span",{class:"clave"}); k.style.borderTopColor = s.color;
    it.append(k, document.createTextNode(s.nombre)); leg.append(it); });
}
function renderInstrumentos(){
  const tb = $("#tablaInstrumentos tbody"); tb.textContent = "";
  for(const sim of D.simbolos){
    const tr = el("tr",{"data-s":sim.s});
    const c1 = el("td"); c1.append(el("span",{class:"sim"},sim.s), el("span",{class:"tipo"},sim.t)); tr.append(c1);
    tr.append(el("td",{}, (sim.m==="USD"?"US$ ":"$ ") + fmtNum(sim.c[sim.c.length-1])));
    for(const n of [1, 21]){
      const v = variacion(sim.a, n), td = el("td");
      if(v==null) td.textContent = "–";
      else{ td.textContent = (v>=0?"▲ ":"▼ ") + fmtPct(v); td.style.color = v>=0?"var(--up)":"var(--down)"; }
      tr.append(td);
    }
    const cob = Math.round(100 * sim.va.reduce((a,b)=>a+b,0) / sim.va.length);
    tr.append(el("td",{class:"oc-movil"}, cob + "%"));
    const tdSpark = el("td",{class:"oc-movil"}); sparkline(tdSpark, sim.a.slice(-63)); tr.append(tdSpark);
    tr.addEventListener("click", () => { simboloSel = sim.s; $("#selSimbolo").value = sim.s;
      cambiarVista("resumen"); });
    tb.append(tr);
  }
}
function renderSalud(){
  const tb = $("#tablaSalud tbody"); tb.textContent = "";
  for(const r of D.salud){
    const tr = el("tr");
    tr.append(el("td",{}, r.ts.replace("T"," ").replace("Z","")));
    tr.append(el("td",{}, r.p));
    const td = el("td"); td.append(el("span",{class:"badge "+r.r}, r.r)); tr.append(td);
    tr.append(el("td",{}, String(r.ob ?? "–")));
    tr.append(el("td",{}, String(r.va ?? "–")));
    tr.append(el("td",{}, String(r.in ?? "–")));
    tr.append(el("td",{class:"oc-movil"}, String(r.ca ?? "–")));
    tb.append(tr);
  }
}
function renderVista(){
  if(vista==="resumen"){ renderTiles(); renderPrincipal(); }
  else if(vista==="precios") renderPrecios();
  else if(vista==="mep") renderMep();
  else if(vista==="instrumentos") renderInstrumentos();
  else if(vista==="salud") renderSalud();
}
function cambiarVista(v){
  vista = v;
  document.querySelectorAll("#menu button").forEach(b => b.classList.toggle("activo", b.dataset.v===v));
  document.querySelectorAll("main section").forEach(s => s.classList.toggle("oculto", s.id !== "v-"+v));
  renderVista();
}
function arrancar(){
  $("#login").classList.add("oculto");
  $("#app").classList.remove("oculto");
  $("#fGen").textContent = new Date(CFG.generado).toLocaleString("es-AR",
      {dateStyle:"medium", timeStyle:"short"}) + " hs";
  const sel = $("#selSimbolo");
  D.simbolos.forEach(s => sel.append(el("option",{value:s.s}, s.s)));
  sel.addEventListener("change", () => { simboloSel = sel.value; renderPrincipal(); });
  $("#togSerie").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    modoSerie = b.dataset.m;
    $("#togSerie").querySelectorAll("button").forEach(x=>x.classList.remove("activo"));
    b.classList.add("activo"); renderPrincipal();
  }));
  $("#togPrecios").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    modoPrecios = b.dataset.m;
    $("#togPrecios").querySelectorAll("button").forEach(x=>x.classList.remove("activo"));
    b.classList.add("activo"); renderPrecios();
  }));
  $("#btnExcel").addEventListener("click", descargarXlsx);
  document.querySelectorAll("#menu button").forEach(b =>
    b.addEventListener("click", () => cambiarVista(b.dataset.v)));
  renderRangos();
  renderInstrumentos();   // deja la tabla lista para la selección cruzada
  cambiarVista("resumen");
  vigilarActualizaciones();
  window.addEventListener("resize", () => renderVista());
}
intentarSesionGuardada().then(ok => { if(ok) arrancar(); });
