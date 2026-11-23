// Mohur desktop app, main process. It owns the engine and the keys; the
// window is sandboxed, has no Node, loads only the app's own files and
// reaches the engine through the few calls preload.cjs exposes.
import { app, BrowserWindow, dialog, ipcMain, Menu, safeStorage, session, shell } from 'electron';
import crypto from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { Engine } from './core/engine.mjs';
import { Net } from './core/net.mjs';
import { Vault } from './core/vault.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const rendererDir = path.join(here, 'renderer');
const indexURL = pathToFileURL(path.join(rendererDir, 'index.html')).href;

// --profile=name keeps a separate person on the same computer (for trying two
// people side by side). Names are letters and digits only.
const profileArg = process.argv.find((a) => a.startsWith('--profile='));
const profile = profileArg ? profileArg.slice(10).replace(/[^a-zA-Z0-9]/g, '').slice(0, 32) : '';
if (profile) app.setPath('userData', path.join(app.getPath('appData'), 'Mohur', 'profiles', profile));

if (!app.requestSingleInstanceLock()) app.quit();

let win = null;
let engine = null;

async function vaultKey() {
  const file = path.join(app.getPath('userData'), 'vault.key');
  if (!(await safeStorage.isAsyncEncryptionAvailable())) throw new Error('This computer has no protected storage for keys, so Mohur cannot keep them safely.');
  try {
    const sealed = await fs.readFile(file);
    const { result, shouldReEncrypt } = await safeStorage.decryptStringAsync(sealed);
    if (shouldReEncrypt) await fs.writeFile(file, await safeStorage.encryptStringAsync(result), { mode: 0o600 });
    return Buffer.from(result, 'base64');
  } catch (e) {
    if (e.code !== 'ENOENT') throw e;
  }
  const key = crypto.randomBytes(32);
  await fs.mkdir(path.dirname(file), { recursive: true });
  await fs.writeFile(file, await safeStorage.encryptStringAsync(key.toString('base64')), { mode: 0o600, flag: 'wx' });
  return key;
}

async function openEngine() {
  const vault = await Vault.open(path.join(app.getPath('userData'), 'vault.bin'), vaultKey);
  // MOHUR_RESOLVER and MOHUR_EXTRA_CA exist for a company's private DNS or CA
  // and for the local lab. Certificates are verified either way.
  let extraCA;
  if (process.env.MOHUR_EXTRA_CA) extraCA = await fs.readFile(process.env.MOHUR_EXTRA_CA, 'utf8');
  const net = new Net({ resolver: process.env.MOHUR_RESOLVER || undefined, extraCA });
  const e = new Engine(vault, net, { label: os.hostname().slice(0, 60) || 'Computer', log: (m) => console.log('[mohur]', m) });
  e.on('update', () => win && !win.isDestroyed() && win.webContents.send('update'));
  return e;
}

function fromApp(event) {
  return event.senderFrame && event.senderFrame.url === indexURL;
}

function handle(name, fn) {
  ipcMain.handle(name, async (event, arg) => {
    if (!fromApp(event)) throw new Error('refused');
    return fn(arg);
  });
}

const str = (v, max) => {
  if (typeof v !== 'string' || v.length > max) throw new Error('refused');
  return v;
};

function wire() {
  handle('state', () => engine.snapshot());
  handle('preview-invite', (text) => engine.previewInvite(str(text, 300)));
  handle('join', async (text) => {
    const me = await engine.join(str(text, 300));
    await engine.syncContacts().catch(() => {});
    engine.start();
    return me;
  });
  handle('send', ({ to, text } = {}) => engine.sendText(str(to, 300), str(text, 20000)));
  handle('send-file', async ({ to } = {}) => {
    str(to, 300);
    const pick = await dialog.showOpenDialog(win, { title: 'Send a file', properties: ['openFile'] });
    if (pick.canceled || !pick.filePaths[0]) return null;
    const file = pick.filePaths[0];
    const st = await fs.stat(file);
    if (st.size > 100 * 1024 * 1024) throw new Error('Files can be up to 100 MB.');
    const data = await fs.readFile(file);
    return engine.sendFile(to, { name: path.basename(file), type: '', data });
  });
  handle('save-file', async ({ address, id } = {}) => {
    const f = await engine.openFile(str(address, 300), str(id, 64));
    const target = await dialog.showSaveDialog(win, { title: 'Save file', defaultPath: path.join(app.getPath('downloads'), path.basename(f.name)) });
    if (target.canceled || !target.filePath) return false;
    await fs.writeFile(target.filePath, f.data);
    shell.showItemInFolder(target.filePath);
    return true;
  });
  handle('refresh', () => engine.serial(() => engine.syncContacts(true)));
}

function harden() {
  session.defaultSession.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  app.on('web-contents-created', (_e, contents) => {
    contents.on('will-navigate', (ev) => ev.preventDefault());
    contents.on('will-redirect', (ev) => ev.preventDefault());
    contents.setWindowOpenHandler(() => ({ action: 'deny' }));
    contents.on('will-attach-webview', (ev) => ev.preventDefault());
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1120, height: 740, minWidth: 760, minHeight: 520, show: false, title: 'Mohur',
    backgroundColor: '#f4f6f9', autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(here, 'preload.cjs'), contextIsolation: true, sandbox: true, nodeIntegration: false,
      webSecurity: true, devTools: !app.isPackaged, spellcheck: false,
    },
  });
  win.once('ready-to-show', () => win.show());
  win.loadURL(indexURL);
}

app.on('second-instance', () => {
  if (win) { if (win.isMinimized()) win.restore(); win.focus(); }
});

app.whenReady().then(async () => {
  Menu.setApplicationMenu(Menu.buildFromTemplate([{ role: 'editMenu' }, { role: 'windowMenu' }]));
  harden();
  try {
    engine = await openEngine();
  } catch (e) {
    dialog.showErrorBox('Mohur cannot start', e.message);
    app.quit();
    return;
  }
  wire();
  createWindow();
  if (engine.joined) {
    engine.syncContacts().catch(() => {});
    engine.start();
  }
});

app.on('window-all-closed', async () => {
  if (engine) await engine.stop();
  app.quit();
});
