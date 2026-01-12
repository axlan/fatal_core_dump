// Application state
const listEl = document.getElementById('list');
const viewer = document.getElementById('viewer');
const emptyEl = document.getElementById('empty');
const messageEl = document.getElementById('message');
const msgSubject = document.getElementById('msg-subject');
const msgFrom = document.getElementById('msg-from');
const msgTime = document.getElementById('msg-time');
const msgBody = document.getElementById('msg-body');
const searchInput = document.getElementById('search');

function renderList(filter = '') {
  listEl.innerHTML = '';
  const normalized = filter.trim().toLowerCase();
  const visible = messages.filter(m => {
    if (!normalized) return true;
    return m.subject.toLowerCase().includes(normalized) || m.from.toLowerCase().includes(normalized);
  });

  if (visible.length === 0) {
    listEl.innerHTML = '<div style="padding:18px;color:var(--muted)">No messages</div>';
    return;
  }

  visible.forEach(m => {
    const item = document.createElement('div');
    item.className = 'msg-item ' + (m.unread ? 'unread' : 'read');
    item.setAttribute('role','listitem');
    item.dataset.id = m.id;
    item.innerHTML = `
      <div class="avatar">${m.from.split('@')[0].charAt(0).toUpperCase()}</div>
      <div class="meta">
        <div class="top">
          <div class="from">${escapeHtml(m.from)}</div>
          <div class="time">${m.time}</div>
        </div>
        <div class="subject">${escapeHtml(m.subject)}</div>
      </div>
      <div class="dot" aria-hidden="true"></div>
    `;
    item.addEventListener('click', () => openMessage(m.id));
    listEl.appendChild(item);
  });
}

function openMessage(id) {
  const m = messages.find(x => x.id === id);
  if (!m) return;
  // mark read
  if (m.unread) {
    m.unread = false;
    renderList(searchInput.value);
  }
  emptyEl.style.display = 'none';
  messageEl.style.display = 'block';
  msgSubject.textContent = m.subject;
  msgFrom.textContent = 'From: ' + m.from;
  msgTime.textContent = m.time;
  msgBody.innerHTML = m.body;
  // attach current id to viewer for actions
  messageEl.dataset.current = m.id;
}

function toggleMark() {
  const id = messageEl.dataset.current;
  if (!id) return;
  const m = messages.find(x => x.id === id);
  m.unread = !m.unread;
  renderList(searchInput.value);
}

function deleteCurrent() {
  const id = messageEl.dataset.current;
  if (!id) return;
  messages = messages.filter(x => x.id !== id);
  messageEl.style.display = 'none';
  emptyEl.style.display = 'block';
  renderList(searchInput.value);
}

// simple HTML escape for inserted text nodes
function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c]));
}

// wire up controls
document.getElementById('mark-read').addEventListener('click', toggleMark);
//document.getElementById('delete').addEventListener('click', deleteCurrent);
searchInput.addEventListener('input', ()=>renderList(searchInput.value));

// initial render
renderList();

// expose for console debugging
window._emails = messages;