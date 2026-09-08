const menuToggle = document.querySelector('.menu-toggle');
const nav = document.querySelector('.nav');

fetch('/api/public-config').then(response => response.json()).then(data => {
  document.querySelectorAll('#public-pix-key, #sponsor-pix-key').forEach(key => {
    if (data.pix_key) key.textContent = data.pix_key;
  });
}).catch(() => {});

const copySponsorPix = document.querySelector('#copy-sponsor-pix');
copySponsorPix?.addEventListener('click', async () => {
  const key = document.querySelector('#sponsor-pix-key')?.textContent?.trim();
  const status = document.querySelector('#copy-sponsor-status');
  if (!key || key === 'Carregando…') return;
  try {
    await navigator.clipboard.writeText(key);
    status.textContent = 'Chave Pix copiada.';
  } catch (_) {
    status.textContent = 'Selecione e copie a chave Pix acima.';
  }
});

menuToggle?.addEventListener('click', () => {
  const opened = nav.classList.toggle('open');
  menuToggle.setAttribute('aria-expanded', opened);
});

document.querySelectorAll('a[href^="#"]').forEach((link) => {
  link.addEventListener('click', (event) => {
    nav?.classList.remove('open');
    menuToggle?.setAttribute('aria-expanded', 'false');
    const selector = link.getAttribute('href');
    const target = selector ? document.querySelector(selector) : null;
    if (!target) return;
    event.preventDefault();
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
    history.replaceState(null, '', selector);
  });
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
