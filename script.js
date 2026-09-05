const menuToggle = document.querySelector('.menu-toggle');
const nav = document.querySelector('.nav');

menuToggle?.addEventListener('click', () => {
  const opened = nav.classList.toggle('open');
  menuToggle.setAttribute('aria-expanded', opened);
});

document.querySelectorAll('.nav a').forEach((link) => {
  link.addEventListener('click', () => nav.classList.remove('open'));
});

document.querySelector('#signup-form')?.addEventListener('submit', (event) => {
  event.preventDefault();
  const name = document.querySelector('#name').value.trim().split(' ')[0];
  const message = document.querySelector('.form-message');
  message.textContent = `Obrigado${name ? `, ${name}` : ''}! Seu cadastro foi recebido. Em breve você terá novidades.`;
  event.target.reset();
});
