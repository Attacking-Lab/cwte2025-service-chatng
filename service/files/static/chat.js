
const $ = (sel) => document.querySelector(sel);
const state = {
	base: localStorage.getItem('chatng_base') || location.origin.replace(/\/$/, ''),
	token: localStorage.getItem('chatng_token') || '',
	user: localStorage.getItem('chatng_user') || '',
	friends: '',
	folder: '',
	inbox: [],
	timer: null,
};

const setBase = (v) => {
	state.base = v.replace(/\/$/, '');
	localStorage.setItem('chatng_base', state.base);
	paintStatus();
};
const setToken = (t, u) => {
	state.token = t || '';
	state.user = u || '';
	if (t) {
		localStorage.setItem('chatng_token', t);
		localStorage.setItem('chatng_user', u);
	}
	else {
		localStorage.removeItem('chatng_token');
		localStorage.removeItem('chatng_user');
		state.folder = '';
		state.inbox = [];
	}
	paintStatus();
};

function paintStatus(){
	$('#apiBase').value = state.base;
	$('#whoami').textContent = state.user ? `Logged in as @${state.user}` : 'not logged in';
	$('#connStatus').textContent = state.token ? 'Authenticated' : 'Disconnected';
	$('#friends').textContent = state.friends;
	$('#side-logged-out').style.display = state.user ? 'none' : 'block';
	$('#side-logged-in').style.display = state.user ? 'block' : 'none';
	$('#chat-card').style.display = state.user ? 'block' : 'none';
}

async function checkStatus(){
	if (!state.token) return;
	try {
		state.friends = 'loading ...';
		api('/auth/info', {
			method:'GET',
			headers: headers()
		}).then(info => {
			state.friends = 'friends: ' + info.friends.map(x => `@${x}`).join(', ') + (info.friends.length > 0 ? '' : 'none');
			paintStatus();
		}).catch(error => {
			setToken(false, false);
			paintStatus();
		})
	} catch(e) {
		setToken(false, false);
		paintStatus();
	}
}

function headers(){
	const h = { 'Content-Type': 'application/json' };
	if (state.token) h['Authorization'] = state.token;
	return h;
}
function rawheaders(){
	const h = {};
	if (state.token) h['Authorization'] = state.token;
	return h;
}

function showMsg(target, text, ok=true){
	const el = $(target); el.textContent = text; el.style.color = ok ? 'var(--accent-2)' : 'var(--danger)';
	if (!text) el.removeAttribute('style');
}

function msgView(m){
	const d = new Date((m.timestamp||0)*1000);
	const time = isFinite(d) ? d.toLocaleString() : '';
	const att = m.attachment ? ` · 1 file` : '';
	const file = m.attachment ? ` <a class="file" href="api${m.attachment.url}" target="_blank">📎Attachment</a> ` : '';
	return `
		<div class="message">
			<div class="meta">
				<span class="pill">${escapeHtml(m.sender)} → ${escapeHtml(m.receiver)}</span>
				<span class="muted">${escapeHtml(time)} ${escapeHtml(att)}</span>
			</div>
			<div class="text">${escapeHtml(m.text || '')} ${file}</div>
		</div>
	`;
}
function foldersView(user){
	let folder = document.createElement('div');
	let button = document.createElement('button');
	button.textContent = '@' + user;
	button.style.marginBottom = '2px';
	folder.appendChild(button);
	folder.addEventListener('click', () => {
		state.folder = user;
		$('#toUser').value = user;
		renderMessages();
	}, false);
	return folder;
}

function renderMessages(search = false){
	if (search) {
		$('#inbox').innerHTML = search.map(msgView).join('') || (state.folder == '@search' ? '<div class="muted">No search results.</div>' : '<div class="muted">No messages yet.</div>');
		$('#inbox').scrollTop = $('#inbox').scrollHeight;
	}
	else {
		let chats_folders = $('#chat-folders');
		chats_folders.textContent = '';
		[...new Set([state.user, ...state.inbox.map(msg => (msg.sender != state.user ? msg.sender : msg.receiver))])].forEach(user => {
			let btn = foldersView(user);
			chats_folders.appendChild(btn);
		});

		$('#inbox').innerHTML = state.inbox.filter(msg => (
			(state.folder == state.user) ? 
				(msg.sender == state.folder && msg.receiver == state.folder) :
				(msg.sender == state.folder || msg.receiver == state.folder)
		)).map(msgView).join('') || '<div class="muted">No messages yet.</div>';
		$('#inbox').scrollTop = $('#inbox').scrollHeight;
	}
}

function escapeHtml(s){
	return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#39;'}[c]));
}

async function api(path, opts={}){
	const url = state.base + '/api' + path;
	const resp = await fetch(url, opts);
	if (!resp.ok) {
		const t = await safeText(resp);
		throw new Error(`[${resp.status}] ${t}`);
	}
	const ctype = resp.headers.get('content-type') || '';
	return ctype.includes('application/json') ? resp.json() : resp.text();
}
async function safeText(r){ try { return await r.text(); } catch { return ''; } }

async function register(){
	const username = $('#regUser').value.trim();
	const password = $('#regPass').value;
	if(!username || !password) return showMsg('#authMsg', 'Username & password required', false);
	try {
		await api('/auth/register', { method:'POST', headers: headers(), body: JSON.stringify({username, password})});
		showMsg('#authMsg', `User @${username} created`);
	} catch(e){
		showMsg('#authMsg', e.message, false);
	}
}

async function login(){
	const username = $('#loginUser').value.trim();
	const password = $('#loginPass').value;
	if(!username || !password) return showMsg('#authMsg', 'Username & password required', false);
	try {
		const data = await api('/auth/login', { method:'POST', headers: headers(), body: JSON.stringify({username, password})});
		setToken(data.token, data.username);
		showMsg('#authMsg', `Logged in as @${username}`);
		checkStatus();
		refreshInbox();
	} catch(e){
		showMsg('#authMsg', e.message, false);
	}
}

async function create(){
	const username = $('#botName').value.trim();
	const token = $('#botToken').value;
	if(!username || !token) return showMsg('#botMsg', 'Bot name & token required', false);
	try {
		await api('/auth/register_bot', { method:'POST', headers: headers(), body: JSON.stringify({username, token})});
		showMsg('#botMsg', `Bot @${username} created`);
	} catch(e) {
		showMsg('#botMsg', e.message, false);
	}
}

async function getLink(){
	const sender = state.user;
	const receiver = state.folder;
	try {
		const res = await api('/chat/share', { method:'POST', headers: headers(), body: JSON.stringify({sender, receiver})});
		prompt('Here is your link:', window.location.origin + '/api' + res['url']);
	} catch(e) {
		alert(e.message);
	}
}
async function loadFromLink(link){
	const code = link.split('/shared/')[1];
	try {
		const msgs = await api('/chat/shared/' + code, { method:'GET', headers: headers()});
		renderMessages(msgs);
	} catch(e) {
		alert(e.message);
	}
}

function logout(){ setToken('', ''); renderMessages(); }

async function sendMessage(){
	const receiver = $('#toUser').value.trim();
	const text = $('#msgText').value;
	if(!receiver || !text) return;
	try {
		await api('/chat/send', { method:'POST', headers: headers(), body: JSON.stringify({receiver, text})});
		$('#msgText').value = '';
		state.folder = receiver;
		refreshInbox();
	} catch(e) {
		console.error(e.message);
		alert(e.message);
	}
}

async function refreshInbox(){
	if(!state.token) {
		state.folder = '';
		state.inbox = [];
		renderMessages();
	}
	try {
		const msgs = await api('/chat/inbox', { headers: headers() });
		state.inbox = msgs;
		renderMessages();
	} catch(e) {
		console.error(e);
	}
}

async function doSearch(){
	let query = $('#searchQ').value.trim();
	if (query.startsWith('/') && (query.endsWith('/') || query.endsWith('/i'))) {
		if (query.endsWith('/i')) {
			query = {
				"$regex": query.slice(1, -2),
				"$options": "i"
			}
		}
		else {
			query = {
				"$regex": query.slice(1, -1)
			}
		}
	}
	else {
		query = {"$regex": RegExp.escape(query)};
	}
	try {
		const res = await api('/search/run', {
			method: 'POST',
			headers: headers(),
			body: JSON.stringify({text: query})
		});
		state.folder = '@search';
		renderMessages(res);
	} catch(e) {
		console.error(e.message);
	}
}

async function uploadFile(){
	const file = $('#fileInput').files[0];
	if(!file) return alert('Select a file.');
	console.log(file);
	const fd = new FormData();
	fd.append('file', file);
	try {
		await api('/files/upload', {
			method: 'POST', 
			headers: rawheaders(),
			body: fd
		});
		$('#fileInput').value = '';
		state.folder = state.user;
		showMsg('#fileMsg', 'File was uploaded');
		refreshInbox();
	}
	catch(e) {
		showMsg('#fileMsg', e.message, false);
		console.error(e.message);
	}
}

async function addFriend(){
	const friend = prompt('Insert the username of your new friend:');
	if (!friend || !friend.length) return;

	try {
		await api('/auth/friend', {
			method: 'POST', 
			headers: headers(),
			body: JSON.stringify({friend: friend})
		});
		checkStatus();
	}
	catch(e) {
		console.error(e.message);
	}
}

function setAutoRefresh(ms){
	if (state.timer) clearInterval(state.timer);
	if (+ms > 0) state.timer = setInterval(refreshInbox, +ms);
}

$('#apiBase').addEventListener('change', e => setBase(e.target.value));
$('#btnRegister').addEventListener('click', register);
$('#btnLogin').addEventListener('click', login);
$('#btnCreate').addEventListener('click', create);
$('#btnLogout').addEventListener('click', logout);
$('#btnSend').addEventListener('click', sendMessage);
$('#msgText').addEventListener('keyup', function(event) {
	if (event.key === "Enter") sendMessage();
});

$('#btnRefresh').addEventListener('click', refreshInbox);
$('#btnSearch').addEventListener('click', doSearch);
$('#btnUpload').addEventListener('click', uploadFile);
$('#autoRefresh').addEventListener('change', e => setAutoRefresh(e.target.value));
$('#friends').addEventListener('click', addFriend);

(() => {
	checkStatus();
	paintStatus();
	refreshInbox();
	setAutoRefresh($('#autoRefresh').value);

	if (!$('#apiBase').value) $('#apiBase').value = state.base;
})();
