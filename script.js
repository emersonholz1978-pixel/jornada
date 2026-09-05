const menuToggle = document.querySelector('.menu-toggle');
const nav = document.querySelector('.nav');

menuToggle?.addEventListener('click', () => {
  const opened = nav.classList.toggle('open');
  menuToggle.setAttribute('aria-expanded', opened);
});

document.querySelectorAll('.nav a').forEach((link) => {
  link.addEventListener('click', () => nav.classList.remove('open'));
});

document.querySelector('#signup-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.target;
  const submit = form.querySelector('button[type="submit"]');
  const message = document.querySelector('.form-message');
  submit.disabled = true;
  message.textContent = 'Criando seu acesso…';

  try {
    const response = await fetch('/api/cadastros', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name: document.querySelector('#name').value.trim(),
        email: document.querySelector('#email').value.trim(),
        password: document.querySelector('#password').value,
        consent: form.querySelector('input[type="checkbox"]').checked,
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || 'Não foi possível concluir o cadastro.');
    message.textContent = data.message;
    window.setTimeout(() => { window.location.href = '/aluno'; }, 500);
  } catch (error) {
    message.textContent = error.message;
    submit.disabled = false;
  }
});
