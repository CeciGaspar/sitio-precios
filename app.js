"use strict";
/* Mercado AR — dashboard. Descifra datos.json en el navegador y renderiza:
   Mi cartera (IOL) · Mis inversiones · Mercado (EOD/MEP) · Salud de datos.
   La app es estática; entre corridas sólo cambian datos.json y meta.json. */

let CFG = null, BLOB = null, D = null;
let vista = "cartera";
let rangoCartera = 365, rangoVelas = 183;
let simboloVelas = null, modoVelas = "c";
let unidadRiesgo = "ars";

/* ---------- utilidades y formato (es-AR, números en Plex Mono) ---------- */
const $ = s => document.querySelector(s);
const b64a = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const ab64 = b => btoa(String.fromCharCode(...new Uint8Array(b)));
const diaAFecha = d => new Date(d * 86400000);
const fmtFecha = d => diaAFecha(d).toLocaleDateString("es-AR",{day:"2-digit",month:"short",year:"2-digit",timeZone:"UTC"});
const fmtFechaLarga = d => diaAFecha(d).toLocaleDateString("es-AR",{day:"2-digit",month:"long",year:"numeric",timeZone:"UTC"});
const fmtNum = (v,dec) => v.toLocaleString("es-AR",{minimumFractionDigits:dec??(Math.abs(v)<100?2:0),maximumFractionDigits:dec??(Math.abs(v)<100?2:0)});
const fmtPesos = (v,dec) => "$ " + fmtNum(v,dec);
const fmtPct = (v,dec=2) => (v>0?"+":"") + v.toLocaleString("es-AR",{minimumFractionDigits:dec,maximumFractionDigits:dec}) + "%";
const fmtVol = v => v>=1e9 ? fmtNum(v/1e9,1)+" B" : v>=1e6 ? fmtNum(v/1e6,1)+" M" : v>=1e3 ? fmtNum(v/1e3,1)+" K" : fmtNum(v,0);
const flecha = v => v>=0 ? "▲ " : "▼ ";
function el(tag, attrs, texto){ const e=document.createElement(tag);
  for(const k in attrs||{}) e.setAttribute(k,attrs[k]);
  if(texto!=null) e.textContent=texto; return e; }
const NS = n => document.createElementNS("http://www.w3.org/2000/svg", n);
function svgEl(n, attrs){ const e = NS(n); for(const k in attrs||{}) e.setAttribute(k, attrs[k]); return e; }

const NOMBRES = {
  GGAL:"Grupo Galicia", YPFD:"YPF", PAMP:"Pampa Energía", ALUA:"Aluar",
  TXAR:"Ternium Argentina", BMA:"Banco Macro", CEPU:"Central Puerto",
  COME:"Comercial del Plata", CRES:"Cresud", EDN:"Edenor",
  TGSU2:"Transp. Gas del Sur", TGNO4:"Transp. Gas del Norte", LOMA:"Loma Negra",
  MIRG:"Mirgor", SUPV:"Supervielle", TRAN:"Transener", VALO:"Grupo Fin. Valores",
  BYMA:"BYMA", CVH:"Cablevisión Holding",
  AL30:"Bonar 2030 USD", AL30D:"Bonar 2030 (D)", GD30:"Global 2030 USD", GD30D:"Global 2030 (D)",
  AAPL:"Apple (CEDEAR)", MSFT:"Microsoft (CEDEAR)", GOOGL:"Alphabet (CEDEAR)",
  NVDA:"NVIDIA (CEDEAR)", TSLA:"Tesla (CEDEAR)", KO:"Coca-Cola (CEDEAR)",
};
const nombreDe = s => NOMBRES[s] || "";
const PALETA_DONA = ["var(--accent)","#4f8ef7","#e6b455","#b48ef7","#f0685a","#5ad4e6","#f18fc2","#9db07f","#8a93a6"];

/* ---------- tema claro/oscuro ---------- */
function aplicarTema(t){
  if(t === "light") document.documentElement.setAttribute("data-theme","light");
  else document.documentElement.removeAttribute("data-theme");
  localStorage.setItem("tema", t);
  const lbl = $("#lblTema"); if(lbl) lbl.textContent = t === "light" ? "Modo oscuro" : "Modo claro";
}
$("#btnTema").addEventListener("click", () => {
  aplicarTema(document.documentElement.getAttribute("data-theme") === "light" ? "dark" : "light");
});

/* ---------- datos cifrados ---------- */
const datosListos = (async () => {
  const r = await fetch("datos.json", {cache:"no-store"});
  if(!r.ok) throw new Error("datos.json: HTTP " + r.status);
  const j = await r.json();
  CFG = {salt:j.salt, iv:j.iv, iter:j.iter, generado:j.generado};
  BLOB = j.blob;
})();
datosListos.catch(() => {
  $("#loginError").textContent = "No se pudieron cargar los datos (la página necesita servirse por http).";
});

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
  try{ await datosListos; }
  catch(e){
    $("#loginError").textContent = "No se pudieron cargar los datos (la página necesita servirse por http).";
    btn.disabled = false; btn.textContent = "Ingresar"; return;
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
    }catch(e){ /* offline */ }
  }, 5 * 60 * 1000);
}

/* ---------- derivados ---------- */
const RANGOS = [["1M",31],["6M",183],["1A",365],["5A",1827],["Todo",null]];
function corte(dias, rango){ return rango==null ? -Infinity : dias[dias.length-1] - rango; }
function variacion(vals, n=1){
  if(vals.length < n+1) return null;
  const a = vals[vals.length-1-n], b = vals[vals.length-1];
  return a > 0 ? (b/a - 1) * 100 : null;
}
function mepPrincipal(){ return D.mep["AL30/AL30D"] || Object.values(D.mep)[0] || null; }
function mepUltimo(){ const m = mepPrincipal(); return m ? m.v[m.v.length-1] : null; }
function posiciones(){ return (D.cartera && D.cartera.posiciones) || []; }
function valorARS(p){ const v = p.q * p.u; return p.m === "USD" ? v * (mepUltimo() || 0) : v; }
function totalCartera(){ return posiciones().reduce((a,p) => a + valorARS(p), 0); }

// Serie de valor de la cartera: símbolos con serie en la base escalan por su cierre;
// posiciones en USD escalan por el MEP; el resto queda a valor actual (constante).
function serieEvolucion(rango){
  const base = D.simbolos.find(s => s.s === "AL30") || D.simbolos[0];
  if(!base) return [];
  const c0 = corte(base.d, rango);
  const dias = base.d.filter(d => d >= c0);
  const fuentes = posiciones().map(p => {
    const hoy = valorARS(p);
    const sim = D.simbolos.find(s => s.s === p.s);
    if(sim){
      const m = new Map(); sim.d.forEach((d,i) => m.set(d, sim.c[i]));
      const ult = sim.c[sim.c.length-1];
      return {hoy, m, ult};
    }
    if(p.m === "USD" && mepPrincipal()){
      const mp = mepPrincipal();
      const m = new Map(); mp.d.forEach((d,i) => m.set(d, mp.v[i]));
      return {hoy, m, ult: mp.v[mp.v.length-1]};
    }
    return {hoy, m:null, ult:null};
  });
  const pts = [];
  const previos = fuentes.map(() => null);
  for(const d of dias){
    let total = 0;
    fuentes.forEach((f,i) => {
      if(!f.m){ total += f.hoy; return; }
      const v = f.m.get(d);
      if(v != null) previos[i] = v;
      total += previos[i] != null ? f.hoy * previos[i] / f.ult : f.hoy;
    });
    pts.push([d, total]);
  }
  return pts;
}

/* ---------- charts ---------- */
function sparkline(cont, valores, ancho=120, alto=30, color="var(--accent)"){
  cont.textContent = "";
  if(!valores || valores.length < 2){ cont.textContent = "–"; return; }
  const min = Math.min(...valores), max = Math.max(...valores);
  const X = i => i/(valores.length-1)*(ancho-4)+2, Y = v => alto-3-((v-min)/(max-min||1))*(alto-6);
  const svg = svgEl("svg", {viewBox:`0 0 ${ancho} ${alto}`, width:ancho, height:alto});
  svg.append(svgEl("path", {
    d: valores.map((v,i)=>(i?"L":"M")+X(i).toFixed(1)+" "+Y(v).toFixed(1)).join(""),
    fill:"none", stroke:color, "stroke-width":"1.6", "stroke-linecap":"round"}));
  const uy = Y(valores[valores.length-1]);
  svg.append(svgEl("circle", {cx:X(valores.length-1).toFixed(1), cy:uy.toFixed(1), r:2.4, fill:color}));
  cont.append(svg);
}

function ticksLindos(min, max, n){
  const span = max - min || 1, paso0 = span / n, mag = Math.pow(10, Math.floor(Math.log10(paso0)));
  const paso = [1,2,2.5,5,10].map(m => m*mag).find(p => span/p <= n) || 10*mag;
  const t = []; for(let v = Math.ceil(min/paso)*paso; v <= max + 1e-9; v += paso) t.push(v);
  return t;
}

function areaChart(cont, puntos, opciones){
  const o = Object.assign({alto:290, fmtY:v=>fmtPesos(v,0)}, opciones);
  cont.textContent = "";
  if(!puntos.length){ cont.append(el("div",{style:"color:var(--text-faint);padding:36px 0;text-align:center"},"Sin datos en el rango")); return; }
  const ancho = Math.max(cont.clientWidth || 800, 320), alto = o.alto;
  const M = {t:12, r:14, b:26, l:70};
  const xs = puntos.map(p=>p[0]), ys = puntos.map(p=>p[1]);
  const x0 = xs[0], x1 = xs[xs.length-1];
  let y0 = Math.min(...ys), y1 = Math.max(...ys);
  const mg = (y1-y0)*0.08 || y1*0.04 || 1; y0 -= mg; y1 += mg;
  const X = d => M.l + (d-x0)/(x1-x0||1)*(ancho-M.l-M.r);
  const Y = v => alto-M.b - (v-y0)/(y1-y0||1)*(alto-M.t-M.b);
  const svg = svgEl("svg", {viewBox:`0 0 ${ancho} ${alto}`, width:"100%"});
  const defs = NS("defs");
  const gid = "gradEvo";
  const gr = svgEl("linearGradient", {id:gid, x1:0, y1:0, x2:0, y2:1});
  const st1 = svgEl("stop", {offset:"0%"}); st1.style.stopColor = "var(--accent)"; st1.style.stopOpacity = ".28";
  const st2 = svgEl("stop", {offset:"100%"}); st2.style.stopColor = "var(--accent)"; st2.style.stopOpacity = "0";
  gr.append(st1, st2); defs.append(gr); svg.append(defs);
  for(const t of ticksLindos(y0, y1, 5)){
    svg.append(svgEl("line", {x1:M.l, x2:ancho-M.r, y1:Y(t), y2:Y(t), stroke:"var(--border)"}));
    const tx = svgEl("text", {x:M.l-9, y:Y(t)+3.5, "text-anchor":"end"}); tx.textContent = o.fmtY(t); svg.append(tx);
  }
  const nX = Math.min(5, Math.max(2, Math.floor(ancho/180)));
  for(let i=0;i<=nX;i++){
    const d = x0 + (x1-x0)*i/nX;
    const tx = svgEl("text", {x:X(d), y:alto-8, "text-anchor": i===0?"start":(i===nX?"end":"middle")});
    tx.textContent = fmtFecha(d); svg.append(tx);
  }
  const traza = puntos.map((p,i)=>(i?"L":"M")+X(p[0]).toFixed(1)+" "+Y(p[1]).toFixed(1)).join("");
  svg.append(svgEl("path", {d: traza+`L${X(x1).toFixed(1)} ${alto-M.b}L${X(x0).toFixed(1)} ${alto-M.b}Z`,
                            fill:`url(#${gid})`, stroke:"none"}));
  svg.append(svgEl("path", {d: traza, fill:"none", stroke:"var(--accent)", "stroke-width":"2",
                            "stroke-linecap":"round", "stroke-linejoin":"round"}));
  const u = puntos[puntos.length-1];
  svg.append(svgEl("circle", {cx:X(u[0]).toFixed(1), cy:Y(u[1]).toFixed(1), r:4, fill:"var(--accent)",
                              stroke:"var(--panel)", "stroke-width":2}));
  // hover
  const cross = svgEl("line", {y1:M.t, y2:alto-M.b, stroke:"var(--border-strong)", "stroke-dasharray":"3 3"});
  cross.style.display = "none"; svg.append(cross);
  const dot = svgEl("circle", {r:4, fill:"var(--accent)", stroke:"var(--panel)", "stroke-width":2});
  dot.style.display = "none"; svg.append(dot);
  const tip = el("div",{class:"tooltip oculto"});
  cont.style.position = "relative"; cont.append(svg, tip);
  svg.addEventListener("pointermove", ev => {
    const r = svg.getBoundingClientRect();
    const dx = x0 + ((ev.clientX-r.left)*(ancho/r.width)-M.l)/(ancho-M.l-M.r)*(x1-x0);
    let mejor=0, dist=Infinity;
    puntos.forEach((p,i)=>{ const dd=Math.abs(p[0]-dx); if(dd<dist){dist=dd;mejor=i;} });
    const p = puntos[mejor];
    cross.setAttribute("x1",X(p[0])); cross.setAttribute("x2",X(p[0])); cross.style.display="";
    dot.setAttribute("cx",X(p[0])); dot.setAttribute("cy",Y(p[1])); dot.style.display="";
    tip.textContent=""; tip.classList.remove("oculto");
    tip.append(el("div",{class:"tfecha"}, fmtFechaLarga(p[0])));
    const f = el("div",{class:"fila"}); f.append(el("span",{},"Valor"), el("span",{}, o.fmtY(p[1])));
    tip.append(f);
    const px = (X(p[0])/ancho)*r.width, tw = tip.offsetWidth;
    tip.style.left = Math.min(Math.max(px+14,4), r.width-tw-4)+"px"; tip.style.top = "8px";
  });
  svg.addEventListener("pointerleave", () => { cross.style.display="none"; dot.style.display="none"; tip.classList.add("oculto"); });
}

function dona(cont, legCont, items){  // items: [{et, sub, v}] ordenados desc
  cont.textContent = ""; legCont.textContent = "";
  const total = items.reduce((a,i)=>a+i.v,0) || 1;
  const tam = 168, r = 62, cx = tam/2, cy = tam/2, grosor = 17;
  const svg = svgEl("svg", {viewBox:`0 0 ${tam} ${tam}`, width:tam, height:tam});
  const circ = 2*Math.PI*r;
  let acumulado = 0;
  items.forEach((it,i) => {
    const frac = it.v/total, largo = Math.max(frac*circ - 2.5, 0.5);
    const c = svgEl("circle", {cx, cy, r, fill:"none", "stroke-width":grosor,
      "stroke-dasharray":`${largo} ${circ-largo}`, "stroke-dashoffset":String(-acumulado*circ + circ/4),
      "stroke-linecap":"butt"});
    c.style.stroke = PALETA_DONA[i % PALETA_DONA.length];
    svg.append(c);
    acumulado += frac;
  });
  cont.append(svg);
  const centro = el("div",{class:"centro"});
  centro.append(el("div",{class:"n"}, String(items.length)), el("div",{class:"t"},"activos"));
  cont.append(centro);
  items.forEach((it,i) => {
    const fila = el("div",{class:"item"});
    const sw = el("span",{class:"sw"}); sw.style.background = PALETA_DONA[i % PALETA_DONA.length];
    fila.append(sw, el("span",{class:"mono"}, it.et), el("span",{class:"et"}, it.sub||""),
                el("span",{class:"pc"}, fmtPct(100*it.v/total,1).replace("+","")));
    legCont.append(fila);
  });
}

function velasChart(cont, sim, modo, rango){
  cont.textContent = "";
  const c0 = corte(sim.d, rango);
  const idx = sim.d.map((d,i)=>i).filter(i => sim.d[i] >= c0);
  if(!idx.length){ cont.append(el("div",{style:"color:var(--text-faint);padding:36px 0;text-align:center"},"Sin datos en el rango")); return; }
  const f = i => modo==="a" && sim.c[i] > 0 ? sim.a[i]/sim.c[i] : 1;
  const serie = idx.map(i => ({d:sim.d[i], o:sim.o[i]*f(i), h:sim.h[i]*f(i), l:sim.l[i]*f(i), c:(modo==="a"?sim.a[i]:sim.c[i]), vo:sim.vo[i]}));
  const ancho = Math.max(cont.clientWidth || 860, 320), alto = 320;
  const M = {t:12, r:74, b:26, l:10};
  const plotW = ancho-M.l-M.r, n = serie.length;
  const modoLinea = n > 260;   // velas ilegibles: caemos a línea
  let y0 = Math.min(...serie.map(v=>v.l)), y1 = Math.max(...serie.map(v=>v.h));
  const mg = (y1-y0)*0.06 || y1*0.04 || 1; y0 -= mg; y1 += mg;
  const paso = plotW/n;
  const X = j => M.l + paso*(j+0.5);
  const Y = v => alto-M.b - (v-y0)/(y1-y0||1)*(alto-M.t-M.b);
  const svg = svgEl("svg", {viewBox:`0 0 ${ancho} ${alto}`, width:"100%"});
  for(const t of ticksLindos(y0,y1,5)){
    svg.append(svgEl("line", {x1:M.l, x2:ancho-M.r, y1:Y(t), y2:Y(t), stroke:"var(--border)"}));
    const tx = svgEl("text", {x:ancho-M.r+8, y:Y(t)+3.5, "text-anchor":"start"}); tx.textContent = fmtNum(t); svg.append(tx);
  }
  const nX = Math.min(5, Math.max(2, Math.floor(ancho/180)));
  for(let i=0;i<=nX;i++){
    const j = Math.round((n-1)*i/nX);
    const tx = svgEl("text", {x:X(j), y:alto-8, "text-anchor": i===0?"start":(i===nX?"end":"middle")});
    tx.textContent = fmtFecha(serie[j].d); svg.append(tx);
  }
  if(modoLinea){
    const traza = serie.map((v,j)=>(j?"L":"M")+X(j).toFixed(1)+" "+Y(v.c).toFixed(1)).join("");
    svg.append(svgEl("path",{d:traza, fill:"none", stroke:"var(--accent)", "stroke-width":"1.8",
                             "stroke-linecap":"round", "stroke-linejoin":"round"}));
  }else{
    const cw = Math.min(Math.max(paso*0.65, 1.5), 11);
    for(let j=0;j<n;j++){
      const v = serie[j], sube = v.c >= v.o, col = sube ? "var(--up)" : "var(--down)";
      const w = svgEl("line", {x1:X(j), x2:X(j), y1:Y(v.h), y2:Y(v.l), "stroke-width":1});
      w.style.stroke = col; svg.append(w);
      const yA = Y(Math.max(v.o,v.c)), yB = Y(Math.min(v.o,v.c));
      const cuerpo = svgEl("rect", {x:X(j)-cw/2, y:yA, width:cw, height:Math.max(yB-yA,1), rx:1});
      cuerpo.style.fill = col; svg.append(cuerpo);
    }
  }
  // línea punteada en el último precio + etiqueta sobre el eje derecho
  const ult = serie[n-1].c;
  svg.append(svgEl("line", {x1:M.l, x2:ancho-M.r, y1:Y(ult), y2:Y(ult),
                            stroke:"var(--accent)", "stroke-width":1, "stroke-dasharray":"4 4", opacity:.8}));
  const etq = svgEl("rect", {x:ancho-M.r+2, y:Y(ult)-9, width:M.r-6, height:18, rx:4});
  etq.style.fill = "var(--accent-soft)"; svg.append(etq);
  const etx = svgEl("text", {x:ancho-M.r+8, y:Y(ult)+3.5, "text-anchor":"start"});
  etx.style.fill = "var(--accent)"; etx.style.fontWeight = "600"; etx.textContent = fmtNum(ult); svg.append(etx);
  // hover
  const cross = svgEl("line", {y1:M.t, y2:alto-M.b, stroke:"var(--border-strong)", "stroke-dasharray":"3 3"});
  cross.style.display="none"; svg.append(cross);
  const tip = el("div",{class:"tooltip oculto"});
  cont.style.position = "relative"; cont.append(svg, tip);
  svg.addEventListener("pointermove", ev => {
    const r = svg.getBoundingClientRect();
    const j = Math.min(n-1, Math.max(0, Math.round(((ev.clientX-r.left)*(ancho/r.width)-M.l)/paso - 0.5)));
    const v = serie[j];
    cross.setAttribute("x1",X(j)); cross.setAttribute("x2",X(j)); cross.style.display="";
    tip.textContent=""; tip.classList.remove("oculto");
    tip.append(el("div",{class:"tfecha"}, fmtFechaLarga(v.d)));
    for(const [et,val] of [["Apertura",fmtNum(v.o)],["Máximo",fmtNum(v.h)],["Mínimo",fmtNum(v.l)],
                           ["Cierre",fmtNum(v.c)],["Volumen",fmtVol(v.vo)]]){
      const fila = el("div",{class:"fila"}); fila.append(el("span",{},et), el("span",{},val)); tip.append(fila);
    }
    const px = (X(j)/ancho)*r.width, tw = tip.offsetWidth;
    tip.style.left = Math.min(Math.max(px+14,4), r.width-tw-4)+"px"; tip.style.top = "8px";
  });
  svg.addEventListener("pointerleave", () => { cross.style.display="none"; tip.classList.add("oculto"); });
}

/* ---------- render: controles comunes ---------- */
function renderRangos(cont, actual, alCambiar){
  cont.textContent = "";
  for(const [rot, dias] of RANGOS){
    const b = el("button",{}, rot);
    if(dias===actual) b.classList.add("activo");
    b.addEventListener("click", () => alCambiar(dias));
    cont.append(b);
  }
}

/* ---------- render: Mi cartera ---------- */
function renderCartera(){
  const pos = posiciones(), total = totalCartera(), mep = mepUltimo();
  $("#carteraTotal").textContent = fmtPesos(total, 0);
  const prev = pos.reduce((a,p) => a + valorARS(p)/(1+p.vd/100), 0);
  const delta = total - prev, pct = prev > 0 ? delta/prev*100 : 0;
  const chip = $("#carteraVarDia");
  chip.textContent = flecha(delta) + fmtPesos(Math.abs(delta),0) + " · " + fmtPct(pct);
  chip.classList.toggle("rojo", delta < 0);
  $("#carteraUsd").textContent = mep ? "≈ US$ " + fmtNum(total/mep, 0) + " al MEP" : "";

  const conCosto = pos.filter(p => p.ppc != null);
  const costo = conCosto.reduce((a,p) => a + p.q*p.ppc * (p.m==="USD"?mep:1), 0);
  const valorCC = conCosto.reduce((a,p) => a + valorARS(p), 0);
  const res = valorCC - costo;
  const elMonto = $("#resultadoMonto");
  elMonto.textContent = (res>=0?"+":"−") + fmtPesos(Math.abs(res),0).slice(0);
  elMonto.classList.toggle("up", res>=0); elMonto.classList.toggle("down", res<0);
  $("#resultadoPct").textContent = costo>0 ? fmtPct(res/costo*100) + " sobre el costo" : "";
  $("#resultadoNota").textContent = `Sobre ${conCosto.length} de ${pos.length} posiciones con costo conocido (IOL no informa PPC del resto)`;

  const mp = mepPrincipal();
  if(mp){
    $("#mepValor").textContent = fmtPesos(mp.v[mp.v.length-1], 0);
    const v = variacion(mp.v);
    $("#mepVar").textContent = v!=null ? flecha(v)+fmtPct(v)+" vs rueda anterior" : "";
    $("#mepVar").className = "nota mono " + (v>=0?"up":"down");
    sparkline($("#mepSpark"), mp.v.slice(-30), 150, 34);
  }

  renderRangos($("#rangoCartera"), rangoCartera, d => { rangoCartera = d; renderCartera(); });
  areaChart($("#chartEvolucion"), serieEvolucion(rangoCartera));

  const items = pos.map(p => ({et:p.s, sub:p.n, v:valorARS(p)})).sort((a,b)=>b.v-a.v);
  dona($("#dona"), $("#leyendaDona"), items);

  const tb = $("#tablaPosiciones tbody"); tb.textContent = "";
  for(const p of [...pos].sort((a,b)=>valorARS(b)-valorARS(a))){
    const v = valorARS(p), tr = el("tr");
    const c1 = el("td"); c1.append(el("span",{class:"tick mono"},p.s), el("span",{class:"nom"},p.n)); tr.append(c1);
    tr.append(el("td",{}, fmtNum(p.q, p.q%1?2:0)));
    tr.append(el("td",{}, p.ppc!=null ? fmtNum(p.ppc, 3) : "–"));
    tr.append(el("td",{}, (p.m==="USD"?"US$ ":"$ ") + fmtNum(p.u, p.u<10?3:2)));
    const vd = el("td",{}, flecha(p.vd)+fmtPct(p.vd)); vd.className = p.vd>=0?"up":"down"; tr.append(vd);
    tr.append(el("td",{}, fmtPesos(v,0)));
    tr.append(el("td",{}, fmtNum(100*v/total,1)+" %"));
    tb.append(tr);
  }
  $("#subPosiciones").textContent = pos.length + " posiciones · valuación en pesos al MEP " +
      (mep ? fmtPesos(mep,0) : "–") + " · snapshot IOL " + (D.cartera ? D.cartera.ts.slice(0,10) : "");
}

/* ---------- render: Mis inversiones ---------- */
function renderInversiones(){
  const pos = [...posiciones()].sort((a,b)=>valorARS(b)-valorARS(a));
  const mep = mepUltimo();
  const tb = $("#tablaInversiones tbody"); tb.textContent = "";
  let tCosto = 0, tValor = 0, tValorCC = 0;
  for(const p of pos){
    const v = valorARS(p);
    const costo = p.ppc!=null ? p.q*p.ppc*(p.m==="USD"?mep:1) : null;
    tValor += v;
    if(costo!=null){ tCosto += costo; tValorCC += v; }
    const tr = el("tr");
    const c1 = el("td");
    const linea = el("div"); linea.append(el("span",{class:"tick mono"},p.s), el("span",{class:"nom"},p.n));
    c1.append(linea);
    const spark = el("span",{class:"chispa"});
    const sim = D.simbolos.find(s => s.s === p.s);
    if(sim) sparkline(spark, sim.c.slice(-30), 90, 22, "var(--text-faint)");
    else spark.textContent = "";
    c1.append(spark); tr.append(c1);
    tr.append(el("td",{}, fmtNum(p.q, p.q%1?2:0)));
    tr.append(el("td",{}, p.ppc!=null ? fmtNum(p.ppc,3) : "–"));
    tr.append(el("td",{}, (p.m==="USD"?"US$ ":"$ ") + fmtNum(p.u, p.u<10?3:2)));
    tr.append(el("td",{}, costo!=null ? fmtPesos(costo,0) : "–"));
    tr.append(el("td",{}, fmtPesos(v,0)));
    const tdRes = el("td");
    if(costo!=null){
      const r = v-costo;
      tdRes.textContent = (r>=0?"+":"−")+fmtPesos(Math.abs(r),0)+" · "+fmtPct(costo>0?r/costo*100:0);
      tdRes.className = r>=0?"up":"down";
    } else tdRes.textContent = "–";
    tr.append(tdRes);
    const vd = el("td",{}, flecha(p.vd)+fmtPct(p.vd)); vd.className = p.vd>=0?"up":"down"; tr.append(vd);
    tb.append(tr);
  }
  const tf = $("#tablaInversiones tfoot"); tf.textContent = "";
  const tr = el("tr");
  tr.append(el("td",{},"Total"), el("td",{},""), el("td",{},""), el("td",{},""));
  tr.append(el("td",{}, tCosto>0 ? fmtPesos(tCosto,0) : "–"));
  tr.append(el("td",{}, fmtPesos(tValor,0)));
  const rT = tValorCC - tCosto;
  const tdR = el("td",{}, tCosto>0 ? (rT>=0?"+":"−")+fmtPesos(Math.abs(rT),0)+" · "+fmtPct(rT/tCosto*100) : "–");
  tdR.className = rT>=0?"up":"down"; tr.append(tdR);
  tr.append(el("td",{},""));
  tf.append(tr);
  $("#subInversiones").textContent = "Snapshot IOL " + (D.cartera ? D.cartera.ts.replace("T"," ").replace("Z"," UTC") : "");
  $("#notaInversiones").textContent =
      "Costo y resultado sólo donde el PPC es reconstruible desde las operaciones (única compra, sin ventas); IOL no informa PPC en el portafolio.";
}

/* ---------- render: Mercado ---------- */
function statCard(rotulo, valorTxt, notaEl, extraEl){
  const c = el("div",{class:"card stat"});
  c.append(el("div",{class:"rotulo"}, rotulo));
  const v = el("div",{class:"valor mono"});
  if(typeof valorTxt === "string") v.textContent = valorTxt; else v.append(valorTxt);
  c.append(v);
  if(notaEl) c.append(notaEl);
  if(extraEl) c.append(extraEl);
  return c;
}
function renderMercado(){
  const cont = $("#statsMercado"); cont.textContent = "";
  for(const par of ["AL30/AL30D","GD30/GD30D"]){
    const s = D.mep[par]; if(!s) continue;
    const v = variacion(s.v);
    const nota = el("div",{class:"nota mono " + (v>=0?"up":"down")}, v!=null ? flecha(v)+fmtPct(v)+" vs rueda anterior" : "");
    const chispa = el("div",{class:"chispa"});
    const card = statCard("MEP " + par, fmtPesos(s.v[s.v.length-1],0), nota, chispa);
    cont.append(card);
    sparkline(chispa, s.v.slice(-30), 150, 30);
  }
  const ult = D.salud[0];
  if(ult){
    const badge = el("span",{class:"badge "+ult.r}, ult.r);
    const nota = el("div",{class:"nota mono"},
        `${ult.va??0} válidas · ${ult.in??0} sospechosas · latencia ${Math.round(ult.du??0)}s`);
    cont.append(statCard("Última corrida ("+ult.p+")", badge, nota));
  }
  cont.append(statCard("Universo", String(D.simbolos.length),
      el("div",{class:"nota"},"instrumentos seguidos")));

  if(!simboloVelas) simboloVelas = D.simbolos[0].s;
  const sel = $("#selInstrumento");
  if(!sel.options.length){
    D.simbolos.forEach(s => sel.append(el("option",{value:s.s}, s.s)));
    sel.addEventListener("change", () => { simboloVelas = sel.value; renderVelas(); });
  }
  sel.value = simboloVelas;
  renderRangos($("#rangoVelas"), rangoVelas, d => { rangoVelas = d; renderVelas(); });
  renderVelas();
  renderTablaInstrumentos();
}
function renderVelas(){
  const sim = D.simbolos.find(s => s.s === simboloVelas) || D.simbolos[0];
  simboloVelas = sim.s;
  $("#tituloVelas").textContent = sim.s + (nombreDe(sim.s) ? " — " + nombreDe(sim.s) : "");
  const c0 = corte(sim.d, rangoVelas), n = sim.d.filter(d=>d>=c0).length;
  $("#subVelas").textContent = `${sim.t} · ${sim.m} · cierre ${modoVelas==="a"?"ajustado":"crudo"} · ${n} ruedas` +
      (n > 260 ? " (línea: demasiadas velas para el ancho)" : "");
  velasChart($("#chartVelas"), sim, modoVelas, rangoVelas);
  document.querySelectorAll("#tablaInstrumentos tbody tr").forEach(tr =>
      tr.classList.toggle("sel", tr.dataset.s === sim.s));
}
function renderTablaInstrumentos(){
  const tb = $("#tablaInstrumentos tbody"); tb.textContent = "";
  for(const sim of D.simbolos){
    const tr = el("tr",{"data-s":sim.s});
    const c1 = el("td"); c1.append(el("span",{class:"tick mono"},sim.s), el("span",{class:"nom"}, nombreDe(sim.s) || sim.t)); tr.append(c1);
    tr.append(el("td",{}, (sim.m==="USD"?"US$ ":"$ ") + fmtNum(sim.c[sim.c.length-1])));
    const v = variacion(sim.c), vd = el("td",{}, v!=null ? flecha(v)+fmtPct(v) : "–");
    vd.className = v>=0?"up":"down"; tr.append(vd);
    const tdS = el("td"); sparkline(tdS, sim.c.slice(-30), 100, 24, "var(--text-faint)"); tr.append(tdS);
    tr.append(el("td",{}, fmtVol(sim.vo[sim.vo.length-1])));
    tr.addEventListener("click", () => { simboloVelas = sim.s; $("#selInstrumento").value = sim.s;
      renderVelas(); $("#chartVelas").scrollIntoView({behavior:"smooth", block:"center"}); });
    tb.append(tr);
  }
}

/* ---------- render: Riesgo ---------- */
const fmtFrac = (v, dec=2) => v==null ? "–" : fmtNum(v*100, dec) + " %";
const fmtRatio = v => v==null ? "–" : fmtNum(v, 2);
function monedaRiesgo(){ return unidadRiesgo==="usd" ? "US$ " : "$ "; }

function renderRiesgo(){
  const R = D.riesgo;
  const cont = $("#statsRiesgo"); cont.textContent = "";
  if(!R){
    cont.append(el("div",{class:"card stat"},"Sin datos de riesgo en esta corrida."));
    return;
  }
  const u = unidadRiesgo, C = R.cartera ? R.cartera[u] : null;
  const valor = R.cartera ? (u==="usd" ? R.cartera.valor_usd : R.cartera.valor_ars) : null;
  const rf = R.rf[u];
  $("#pillRiesgo").textContent =
      `VaR histórico · ventana ${R.ventana_var} ruedas · MEP ${R.mep_par} · rf ${fmtNum(rf*100,1)} %`;

  const monto = f => (f!=null && valor!=null) ? monedaRiesgo() + fmtNum(f*valor, 0) : "–";
  const carta = (rot, fr, sub) => {
    const nota = el("div",{class:"nota mono"}, fr!=null ? fmtFrac(fr) + (sub ? " · " + sub : "") : (sub||""));
    return statCard(rot, monto(fr), nota);
  };
  if(C){
    cont.append(carta("VaR 95 diario", C.var95, C.var95p!=null ? "paramétrico " + fmtFrac(C.var95p) : ""));
    cont.append(carta("CVaR 95 (Expected Shortfall)", C.cvar95, C.cvar99!=null ? "al 99: " + fmtFrac(C.cvar99) : ""));
    const vol = statCard("Volatilidad 90d anualizada", C.vol.v90!=null ? fmtFrac(C.vol.v90,1) : "–",
        el("div",{class:"nota mono"}, `30d ${fmtFrac(C.vol.v30,1)} · 252d ${fmtFrac(C.vol.v252,1)}`));
    cont.append(vol);
    cont.append(statCard("Drawdown máximo", C.dd_max!=null ? fmtFrac(C.dd_max,1) : "–",
        el("div",{class:"nota mono"}, "en curso: " + fmtFrac(C.dd_actual,1))));
  }else{
    cont.append(statCard("Cartera", "–", el("div",{class:"nota"},"sin snapshot de cartera en esta corrida")));
  }

  const pr = $("#panelRatios"); pr.textContent = "";
  if(C){
    const grilla = el("div",{class:"panelRatios"});
    const celda = (r, v, clase) => { const c = el("div",{class:"celda"});
      c.append(el("div",{class:"r"},r)); const vv = el("div",{class:"v "+(clase||"")}, v); c.append(vv); return c; };
    const col = v => v==null ? "" : (v>=0 ? "up" : "down");
    grilla.append(
      celda("Ret. día", fmtFrac(C.ret.d), col(C.ret.d)),
      celda("Ret. mes", fmtFrac(C.ret.m), col(C.ret.m)),
      celda("Ret. año", fmtFrac(C.ret.a), col(C.ret.a)),
      celda("Sharpe", fmtRatio(C.sharpe), col(C.sharpe)),
      celda("Sortino", fmtRatio(C.sortino), col(C.sortino)),
      celda("VaR 99 diario", C.var99!=null ? monto(C.var99) : "–"),
    );
    pr.append(grilla);
    $("#subRatios").textContent = `Valor: ${monedaRiesgo()}${fmtNum(valor,0)} · retornos log agregados · rf anual ${fmtNum(rf*100,1)} %`;
  }else{
    $("#subRatios").textContent = "";
    pr.append(el("div",{class:"notita"},"Sin cartera para calcular ratios."));
  }

  const pc = $("#panelCobertura"); pc.textContent = "";
  if(R.cartera){
    const cob = R.cartera.cobertura;
    const barra = el("div",{class:"barraCob"});
    const fill = el("div"); fill.style.width = (100*cob)+"%"; barra.append(fill);
    pc.append(el("div",{class:"valor mono", style:"font-size:22px;font-weight:600"}, fmtFrac(cob,1)));
    pc.append(barra);
    pc.append(el("div",{class:"notita"},
        R.cartera.sin_serie.length
          ? "Sin serie histórica (entran a valor constante, riesgo no modelado): " + R.cartera.sin_serie.join(", ")
          : "Todas las posiciones tienen serie histórica."));
  }

  const tb = $("#tablaRiesgo tbody"); tb.textContent = "";
  const orden = [...R.activos].sort((a,b) => (b[u].var95 ?? -1) - (a[u].var95 ?? -1));
  for(const a of orden){
    const m = a[u], tr = el("tr");
    const c1 = el("td"); c1.append(el("span",{class:"tick mono"},a.s), el("span",{class:"nom"}, nombreDe(a.s)||"")); tr.append(c1);
    tr.append(el("td",{}, fmtFrac(m.vol.v90,1)));
    tr.append(el("td",{}, fmtFrac(m.var95)));
    tr.append(el("td",{}, fmtFrac(m.cvar95)));
    tr.append(el("td",{}, fmtFrac(m.var99)));
    tr.append(el("td",{}, fmtFrac(m.dd_max,1)));
    const sh = el("td",{}, fmtRatio(m.sharpe)); sh.className = m.sharpe==null ? "" : (m.sharpe>=0?"up":"down");
    tr.append(sh);
    tb.append(tr);
  }
  $("#subRiesgoActivos").textContent = `${R.activos.length} instrumentos · medición en ${u==="usd"?"dólar MEP":"pesos"}`;
  renderHeatmap(R.correl);
}

function renderHeatmap(correl){
  const cont = $("#correlHeat"); cont.textContent = "";
  const s = correl.s, m = correl.m;
  if(!s.length){ cont.append(el("div",{class:"notita"},"Sin ruedas comunes suficientes para correlacionar.")); return; }
  const celda = 24, margen = 52, n = s.length;
  const tam = margen + n*celda + 6;
  const svg = svgEl("svg", {viewBox:`0 0 ${tam} ${tam}`, width:Math.min(tam, 640)});
  const colorDe = v => {
    const t = Math.min(Math.abs(v), 1);
    return v >= 0 ? `color-mix(in srgb, var(--accent) ${Math.round(t*85)}%, var(--panel-2))`
                  : `color-mix(in srgb, var(--down) ${Math.round(t*85)}%, var(--panel-2))`;
  };
  for(let i=0;i<n;i++){
    const ty = svgEl("text", {x:margen-6, y:margen + i*celda + celda/2 + 3.5, "text-anchor":"end", class:"eje"});
    ty.textContent = s[i]; svg.append(ty);
    const tx = svgEl("text", {x:margen + i*celda + celda/2, y:margen-8, "text-anchor":"start", class:"eje",
                              transform:`rotate(-45 ${margen + i*celda + celda/2} ${margen-8})`});
    tx.textContent = s[i]; svg.append(tx);
    for(let j=0;j<n;j++){
      const r = svgEl("rect", {x:margen + j*celda + 1, y:margen + i*celda + 1,
                               width:celda-2, height:celda-2, rx:3});
      r.style.fill = colorDe(m[i][j]);
      const titulo = NS("title");
      titulo.textContent = `${s[i]} × ${s[j]}: ${fmtNum(m[i][j],2)}`;
      r.append(titulo);
      svg.append(r);
    }
  }
  cont.append(svg);
}

/* ---------- render: Salud ---------- */
function renderSalud(){
  const cont = $("#statsSalud"); cont.textContent = "";
  const cob = D.simbolos.map(s => s.va.reduce((a,b)=>a+b,0)/s.va.length);
  const cobProm = 100*cob.reduce((a,b)=>a+b,0)/(cob.length||1);
  const ruedas = Math.max(...D.simbolos.map(s=>s.d.length), 0);
  const sospechosas = D.simbolos.reduce((a,s)=>a+s.va.filter(v=>!v).length, 0);
  const ult = D.salud[0];
  cont.append(statCard("Cobertura", fmtNum(cobProm,1)+" %", el("div",{class:"nota"},"promedio de ruedas válidas")));
  cont.append(statCard("Ruedas", fmtNum(ruedas,0), el("div",{class:"nota"},"histórico máximo por símbolo")));
  cont.append(statCard("Sospechosas", fmtNum(sospechosas,0), el("div",{class:"nota"},"barras marcadas inválidas")));
  cont.append(statCard("Latencia", ult ? fmtNum(Math.round(ult.du??0),0)+" s" : "–",
      el("div",{class:"nota"},"última corrida "+(ult?ult.p:""))));

  const lista = $("#listaCompletitud"); lista.textContent = "";
  const orden = [...D.simbolos].sort((a,b) =>
      a.va.reduce((x,y)=>x+y,0)/a.va.length - b.va.reduce((x,y)=>x+y,0)/b.va.length);
  for(const s of orden){
    const pc = 100*s.va.reduce((a,b)=>a+b,0)/s.va.length;
    const item = el("div",{class:"itemCompletitud"});
    const et = el("div",{class:"et"}); et.append(el("span",{class:"tick mono"},s.s), el("span",{class:"nom"}, nombreDe(s.s)||s.t));
    const barra = el("div",{class:"barra"});
    const fill = el("div"); fill.style.width = pc+"%"; if(pc < 98) fill.classList.add("baja");
    barra.append(fill);
    const estado = el("div",{class:"estado " + (pc>=98?"up":"")}, pc>=98 ? "OK" : "revisar");
    if(pc<98) estado.style.color = "#b9862f";
    item.append(et, barra, el("div",{class:"pc"}, fmtNum(pc,1)+" %"), estado);
    lista.append(item);
  }
  const tb = $("#tablaSalud tbody"); tb.textContent = "";
  for(const r of D.salud){
    const tr = el("tr");
    tr.append(el("td",{}, r.ts.replace("T"," ").replace("Z","")));
    tr.append(el("td",{}, r.p));
    const td = el("td"); td.append(el("span",{class:"badge "+r.r}, r.r)); tr.append(td);
    tr.append(el("td",{}, String(r.ob ?? "–")));
    tr.append(el("td",{}, String(r.va ?? "–")));
    tr.append(el("td",{}, String(r.in ?? "–")));
    tr.append(el("td",{}, r.du!=null ? Math.round(r.du)+" s" : "–"));
    tb.append(tr);
  }
}

/* ---------- navegación ---------- */
const PAGINAS = {
  cartera:      ["Mi cartera", "Posiciones y valuación · IOL"],
  inversiones:  ["Mis inversiones", "Detalle de posiciones y resultado"],
  mercado:      ["Mercado", "EOD · dólar MEP"],
  riesgo:       ["Riesgo", "VaR, CVaR, volatilidad y correlaciones · en pesos y dólar MEP"],
  salud:        ["Salud de datos", "Ingesta y completitud del histórico"],
};
function renderVista(){
  if(vista==="cartera") renderCartera();
  else if(vista==="inversiones") renderInversiones();
  else if(vista==="mercado") renderMercado();
  else if(vista==="riesgo") renderRiesgo();
  else if(vista==="salud") renderSalud();
}
function cambiarVista(v){
  vista = v;
  document.querySelectorAll("#menu button").forEach(b => b.classList.toggle("activo", b.dataset.v===v));
  document.querySelectorAll("main section").forEach(s => s.classList.toggle("oculto", s.id !== "v-"+v));
  $("#tituloPagina").textContent = PAGINAS[v][0];
  $("#subPagina").textContent = PAGINAS[v][1];
  renderVista();
}
function arrancar(){
  $("#login").classList.add("oculto");
  $("#app").classList.remove("oculto");
  aplicarTema(localStorage.getItem("tema") === "light" ? "light" : "dark");
  $("#fGen").textContent = new Date(CFG.generado).toLocaleString("es-AR",{dateStyle:"medium", timeStyle:"short"});
  $("#togVelas").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    modoVelas = b.dataset.m;
    $("#togVelas").querySelectorAll("button").forEach(x=>x.classList.remove("activo"));
    b.classList.add("activo"); renderVelas();
  }));
  $("#togUnidad").querySelectorAll("button").forEach(b => b.addEventListener("click", () => {
    unidadRiesgo = b.dataset.u;
    $("#togUnidad").querySelectorAll("button").forEach(x=>x.classList.remove("activo"));
    b.classList.add("activo"); renderRiesgo();
  }));
  document.querySelectorAll("#menu button").forEach(b =>
      b.addEventListener("click", () => cambiarVista(b.dataset.v)));
  cambiarVista(posiciones().length ? "cartera" : "mercado");
  vigilarActualizaciones();
  let timer = null;
  window.addEventListener("resize", () => { clearTimeout(timer); timer = setTimeout(renderVista, 150); });
}
intentarSesionGuardada().then(ok => { if(ok) arrancar(); });
