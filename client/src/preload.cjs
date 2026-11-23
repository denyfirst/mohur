// The window's only way to the engine: a handful of calls with plain values.
// No keys, files, paths or network access pass through here.
const { contextBridge, ipcRenderer } = require('electron');

const call = (name, arg) => ipcRenderer.invoke(name, arg).catch((e) => {
  throw new Error(String(e && e.message || e).replace(/^Error invoking remote method '[^']+': (Error: )?/, ''));
});

contextBridge.exposeInMainWorld('mohur', {
  state: () => call('state'),
  previewInvite: (text) => call('preview-invite', String(text)),
  join: (text) => call('join', String(text)),
  send: (to, text) => call('send', { to: String(to), text: String(text) }),
  sendFile: (to) => call('send-file', { to: String(to) }),
  saveFile: (address, id) => call('save-file', { address: String(address), id: String(id) }),
  refresh: () => call('refresh'),
  onUpdate: (cb) => { ipcRenderer.on('update', () => cb()); },
});
