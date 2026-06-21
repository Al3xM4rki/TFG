const fecha = new Date();
fecha.setDate(fecha.getDate() - 2);
const ayerISO = fecha.toISOString();

return{
  fecha_filtro: ayerISO
};