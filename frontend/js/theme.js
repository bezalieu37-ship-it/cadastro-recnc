/* Tema claro/escuro global — Cadastro RECNC
   Lê localStorage['tema'] ('claro' | 'escuro') e aplica no documento.
   Usado por todas as páginas; o seletor fica em configurações.html. */
(function () {
  function aplicar() {
    var tema = 'claro';
    try { tema = localStorage.getItem('tema') || 'claro'; } catch (e) {}
    var escuro = (tema === 'escuro');
    document.documentElement.setAttribute('data-bs-theme', escuro ? 'dark' : 'light');
    if (document.body) document.body.classList.toggle('dark-mode', escuro);
  }
  if (document.body) {
    aplicar();
  } else {
    document.addEventListener('DOMContentLoaded', aplicar);
  }
})();
