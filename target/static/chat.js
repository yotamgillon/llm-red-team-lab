const log = document.getElementById('log');
const history = [];
document.getElementById('f').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = document.getElementById('m');
  const message = input.value.trim();
  if (!message) return;
  input.value = '';
  const me = document.createElement('div');
  me.className = 'me';
  me.textContent = 'You: ' + message;   // user text is safe here
  log.appendChild(me);
  const res = await fetch('/api/chat', {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({message, history}),
  });
  const data = await res.json();
  const bot = document.createElement('div');
  bot.className = 'bot';
  // LLM05 SINK (deliberate): model output is injected as HTML without sanitising.
  bot.innerHTML = data.reply_html;
  log.appendChild(bot);
  history.push({role: 'user', content: message}, {role: 'assistant', content: data.reply});
});
