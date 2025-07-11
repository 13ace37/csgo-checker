const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const { autoUpdater } = require('electron-updater');
const isDev = require('electron-is-dev');
const EncryptedStorage = require('./EncryptedStorage.js');
let JSONdb = require('simple-json-db');
const got = require('got');
const User = require('steam-user');
const CSUser = require('globaloffensive');
const SteamTotp = require('steam-totp');
const fs = require('fs');
const path = require('path');
const { EOL } = require('os');
const { penalty_reason_string, protoDecode, protoEncode, penalty_reason_permanent } = require('./helpers/util.js');
const Protos = require('./helpers/protos.js')([{
	name: 'csgo',
	protos: [
		__dirname + '/protos/cstrike15_gcmessages.proto',
		__dirname + '/protos/gcsdk_gcmessages.proto',
		__dirname + '/protos/base_gcmessages.proto',
	]
}]);

app.requestSingleInstanceLock() ? (app.on("second-instance", () => {
	mainWindowCreated ? (win.isMinimized() || win.restore(), win.focus()) : settings.get("encrypted") && (promptWindow.isMinimized() || promptWindow.restore(), promptWindow.focus())
}), app.on("activate", () => {
	0 === BrowserWindow.getAllWindows().length && createWindow()
}), app.whenReady().then(async () => {
	await openDB(), createWindow()
})) : app.quit();


const IS_PORTABLE = process.env.PORTABLE_EXECUTABLE_DIR != null;
const USER_DATA = IS_PORTABLE ? path.join(process.env.PORTABLE_EXECUTABLE_DIR, process.env.PORTABLE_EXECUTABLE_APP_FILENAME + '-data') : app.getPath('userData');
const SETTINGS_PATH = path.join(USER_DATA, 'settings.json');
const ACCOUNTS_PATH = path.join(USER_DATA, 'accounts.json');
const ACCOUNTS_ENCRYPTED_PATH = path.join(USER_DATA, 'accounts.encrypted.json');

if (!fs.existsSync(USER_DATA)) {
	fs.mkdirSync(USER_DATA) //makes data on first run
}

if (isDev) {
	try {
		require('electron-reload')(__dirname);
	} catch (_) { }
}

let steamTimeOffset = null;

let win = null

let passwordPromptResponse = null;

const settings = new JSONdb(SETTINGS_PATH);
settings.sync(); //makes empty file on first run

//will be initialized later
/**
 * @type {JSONdb}
 */
var db = null;

function beforeWindowInputHandler(window, event, input) {
	if (input.control && input.shift && input.key.toLowerCase() === 'i') {
		window.webContents.openDevTools();
		event.preventDefault();
	}
	if (input.control && input.key.toLowerCase() === 'r') {
		window.reload();
	}
}

let promptWindow;

async function openDB() {
	try {
		if (db) {
			db.sync(); //force save before switch
			db = null;
		}
		if (settings.get('encrypted')) {
			let error_message = null;
			while (true) {
				let pass = await new Promise((resolve, reject) => {
					passwordPromptResponse = null;
					promptWindow = new BrowserWindow({
						webPreferences: {
							preload: path.join(__dirname, 'preload.js'),
							contextIsolation: true,
						},
						width: 500,
						height: 280,
						resizable: false,
						show: false
					});
					promptWindow.removeMenu();
					promptWindow.loadFile(__dirname + '/html/password.html').then(() => {
						promptWindow.webContents.send('password_dialog:init', error_message);
					})
					promptWindow.webContents.on('before-input-event', (event, input) => beforeWindowInputHandler(promptWindow, event, input));
					promptWindow.once('ready-to-show', () => promptWindow.show())
					promptWindow.on('closed', () => {
						if (passwordPromptResponse == null) {
							return app.quit();
						}
						resolve(passwordPromptResponse);
						promptWindow = null;
					})
				});
				try {
					if (pass == null || pass.length == 0) {
						throw 'Password can not be empty';
					}
					db = await new Promise((res, rej) => {
						try {
							let db = new EncryptedStorage(ACCOUNTS_ENCRYPTED_PATH, pass);
							db.on('error', rej);//this is for async errors
							db.on('loaded', () => res(db));
						} catch (error) {
							rej(error);
						}
					})
					//we decrypted successfully, exit loop
					break;
				} catch (error) {
					if (typeof error != 'string') {
						if (error.reason == 'BAD_DECRYPT') {
							error = 'Invalid password';
						}
						else if (error.code) {
							error = error.code;
						}
						else {
							error = error.toString();
						}
					}
					error_message = error;
				}
			}
			return;
		}
		db = new JSONdb(ACCOUNTS_PATH);
		db.sync();
	} catch (error) {
		await dialog.showMessageBox(null, {
			title: 'openDB Error',
			message: error.toString(),
			type: 'error'
		});
	}
}

// add some defaults
if (!settings.get('tags')) {
	settings.set('tags', {});
}
if (typeof settings.get('encrypted') != 'boolean') {
	settings.set('encrypted', false);
}

let updated = settings.get('version') != app.getVersion();
settings.set('version', app.getVersion());

var currently_checking = [];

var mainWindowCreated = false;

function createWindow() {

	win = new BrowserWindow({
		webPreferences: {
			preload: path.join(__dirname, 'preload.js'),
			contextIsolation: true,
		},
		width: 1150,
		height: 625,
		minWidth: 1150,
		minHeight: 625
	});
	win.removeMenu();
	win.loadFile(__dirname + '/html/index.html');
	win.webContents.on('before-input-event', (event, input) => beforeWindowInputHandler(win, event, input));
	win.webContents.once('did-finish-load', () => {
		// disable automatic downloads in portable mode
		autoUpdater.autoDownload = !IS_PORTABLE && !isDev;
		autoUpdater.on('update-available', (info) => {
			const { provider } = autoUpdater.updateInfoAndProvider;
			const updateUrl = provider.baseUrl + provider.options.owner + '/' + provider.options.repo + '/releases/latest';
			win.webContents.send('update:available', autoUpdater.autoDownload, updateUrl);
		});
		autoUpdater.on('update-downloaded', (info) => {
			win.webContents.send('update:downloaded');
		});
		autoUpdater.on('error', (err) => {
			console.log(err);
		});
		if (autoUpdater.autoDownload) {
			autoUpdater.checkForUpdatesAndNotify();
		}
		else {
			autoUpdater.checkForUpdates();
		}
	});

	mainWindowCreated = true;
}

/* Moved due to second-instance patch */

// app.whenReady().then(async () => {
//     await openDB();
//     createWindow();
// })

app.on('window-all-closed', () => {
	if (!mainWindowCreated) {
		return;
	}
	if (process.platform !== 'darwin') {
		app.quit();
	}
})

/* Moved due to second-instance patch */

// app.on('activate', () => {
//     if (BrowserWindow.getAllWindows().length === 0) {
//         createWindow();
//     }
// })

ipcMain.on('encryption:password', (_, password) => passwordPromptResponse = password);

ipcMain.handle('encryption:setup', async () => {
	let pass = await new Promise((resolve, reject) => {
		passwordPromptResponse = null;
		let promptWindow = new BrowserWindow({
			parent: win,
			modal: true,
			webPreferences: {
				preload: path.join(__dirname, 'preload.js'),
				contextIsolation: true,
			},
			width: 500,
			height: 375,
			resizable: false,
			show: false
		});
		promptWindow.removeMenu();
		promptWindow.loadFile(__dirname + '/html/encryption_setup.html');
		promptWindow.webContents.on('before-input-event', (event, input) => beforeWindowInputHandler(promptWindow, event, input));
		promptWindow.once('ready-to-show', () => promptWindow.show())
		promptWindow.on('closed', () => {
			if (passwordPromptResponse == null) {
				resolve(null);
			}
			resolve(passwordPromptResponse);
			promptWindow = null;
		})
	});
	if (pass == null) { //no data submitted
		return false;
	}
	try {
		db = await new Promise((res, rej) => {
			try {
				let new_db = new EncryptedStorage(ACCOUNTS_ENCRYPTED_PATH, pass, {
					newData: db.JSON()
				});
				new_db.on('error', rej);//this is for async errors
				new_db.on('loaded', () => res(new_db));
			} catch (error) {
				rej(error);
			}
		});
		//delete plain text file
		fs.unlinkSync(ACCOUNTS_PATH);
		settings.set('encrypted', true);
		return true;
	} catch (error) {
		console.log(error);
		return false;
	}
});

ipcMain.handle('encryption:remove', async () => {
	let error_message = null;
	while (true) {
		let pass = await new Promise((resolve, reject) => {
			passwordPromptResponse = null;
			let promptWindow = new BrowserWindow({
				parent: win,
				modal: true,
				webPreferences: {
					preload: path.join(__dirname, 'preload.js'),
					contextIsolation: true,
				},
				width: 500,
				height: 280,
				resizable: false,
				show: false
			});
			promptWindow.removeMenu();
			promptWindow.loadFile(__dirname + '/html/password.html').then(() => {
				promptWindow.webContents.send('password_dialog:init', error_message, 'Remove encryption');
			})
			promptWindow.webContents.on('before-input-event', (event, input) => beforeWindowInputHandler(promptWindow, event, input));
			promptWindow.once('ready-to-show', () => promptWindow.show())
			promptWindow.on('closed', () => {
				if (passwordPromptResponse == null) {
					resolve(null);
				}
				resolve(passwordPromptResponse);
				promptWindow = null;
			})
		});
		if (pass == null) { //no data submitted
			return true; //true is fail as we are still encrypted
		}
		try {
			if (pass.length == 0) {
				throw 'Password can not be empty';
			}
			//attempt to decrypt using this password
			let temp_db = await new Promise((res, rej) => {
				try {
					let new_db = new EncryptedStorage(ACCOUNTS_ENCRYPTED_PATH, pass);
					new_db.on('error', rej);//this is for async errors
					new_db.on('loaded', () => res(new_db));
				} catch (error) {
					rej(error);
				}
			});
			db = new JSONdb(ACCOUNTS_PATH);
			db.JSON(temp_db.JSON());
			db.sync();

			temp_db = null;

			//delete encrypted file
			fs.unlinkSync(ACCOUNTS_ENCRYPTED_PATH);
			settings.set('encrypted', false);
			return false; //false is success as in non encrypted
		} catch (error) {
			console.log(error);
			if (typeof error != 'string') {
				if (error.reason == 'BAD_DECRYPT') {
					error = 'Invalid password';
				}
				else if (error.code) {
					error = error.code;
				}
				else {
					error = error.toString();
				}
			}
			error_message = error;
		}
	}
});

ipcMain.handle('app:version', app.getVersion);
ipcMain.handle('app:isDev', () => isDev);

ipcMain.handle('accounts:get', () => {
	let data = db.JSON();
	for (const username in data) {
		if (Object.hasOwnProperty.call(data, username)) {
			const account = data[username];
			if (currently_checking.indexOf(username) != -1) {
				account.pending = true;
			}
		}
	}
	let dataArray = [];
	Object.keys(data).forEach(a => {
		let _temp = data[a];
		_temp["_name"] = a;
		dataArray.push(_temp);
	});
	dataArray.sort((a, b) => b.rank - a.rank);
	let sortData = {};
	dataArray.forEach(a => {
		sortData[a["_name"]] = a;
		delete sortData[a["_name"]]["_name"];
	});
	return sortData;
});

async function process_check_account(username) {
	const account = db.get(username);
	if (!account) {
		return { error: 'unable to find account' };
	}

	try {
		const res = await check_account(username, account.password, account.sharedSecret);
		console.log(res);
		for (const key in res) {
			if (Object.hasOwnProperty.call(res, key)) {
				account[key] = res[key];
			}
		}
		db.set(username, account);
		return res;
	} catch (error) {
		console.log(error);
		account.error = error;
		db.set(username, account);
		return { error: error };
	}
}

ipcMain.handle('ready', () => {
	if (win && updated) {
		win.webContents.send('update:changelog', fs.readFileSync(__dirname + '/changelog.md').toString());
	}
});

ipcMain.handle('accounts:check', async (_, username) => await process_check_account(username));

ipcMain.handle('accounts:add', (_, username, password) => db.set(username, { password: password }));

ipcMain.handle('accounts:update', (_, username, data) => {
	let account = db.get(username);
	for (const key in data) {
		account[key] = data[key];
	}
	db.set(username, account);
});

ipcMain.handle('accounts:delete', (_, username) => db.delete(username));

ipcMain.handle('accounts:delete_all', (_) => db.deleteAll());

ipcMain.handle('accounts:import', async (event) => {
	let file = await dialog.showOpenDialog(event.sender, { properties: ['openFile'], });
	if (file.canceled) {
		return;
	}
	file = file.filePaths[0];
	let accs = fs.readFileSync(file).toString().split('\n').map(x => x.trim().split(':')).filter(x => x && x.length == 2);
	accs.forEach(acc => {
		db.set(acc[0], {
			password: acc[1],
		});
	});
	for (const acc of accs) {
		process_check_account(acc[0]);
		await new Promise(p => setTimeout(p, 200));
	}
});

ipcMain.handle('accounts:export', async (event) => {
	let file = await dialog.showSaveDialog({
		defaultPath: 'accounts.txt',
		filters: [
			{
				name: 'Text files',
				extensions: ['txt']
			},
			{
				name: 'All Files',
				extensions: ['*']
			}
		]
	});
	if (file.canceled) {
		return;
	}
	let accs = Object.entries(db.JSON()).map(x => x[0] + ':' + x[1].password).join(EOL);
	fs.writeFileSync(file.filePath, accs);
});

ipcMain.handle("settings:get", (_, type) => settings.get(type));

ipcMain.handle("settings:set", (_, type, value) => settings.set(type, value));

/**
 * Logs on to specified account and performs all checks
 * @param {string} username login
 * @param {string} pass password
 * @param {string} [sharedSecret] mobile authenticator shared secret
 * @returns {Promise}
 */
function check_account(username, pass, sharedSecret) {
	return new Promise((resolve, reject) => {
		sleep = (ms) => {
			return new Promise(resolve => {
				setTimeout(resolve, ms);
			});
		}
		currently_checking.push(username);

		let attempts = 0;
		let Done = false;
		let steamClient = new User();
		let csClient = new CSUser(steamClient);

		steamClient.logOn({
			accountName: username,
			password: pass,
		});

		steamClient.on('disconnected', (eresult, msg) => {
			currently_checking = currently_checking.filter(x => x !== username);
		});

		steamClient.on('error', (e) => {
			let errorStr = ``;
			switch (e.eresult) {
				case 5: errorStr = `Invalid Password`; break;
				case 6:
				case 34: errorStr = `Logged In Elsewhere`; break;
				case 84: errorStr = `Rate Limit Exceeded`; break;
				case 65: errorStr = `steam guard is invalid`; break;
				default: errorStr = `Unknown: ${e.eresult}`; break;
			}
			currently_checking = currently_checking.filter(x => x !== username);
			reject(errorStr);
		});

		steamClient.on('steamGuard', (domain, callback) => {
			if (domain == null && sharedSecret && sharedSecret.length > 0) { //domain will be null for mobile authenticator
				if (steamTimeOffset == null) {
					SteamTotp.getTimeOffset((err, offset) => {
						if (err) {
							currently_checking = currently_checking.filter(x => x !== username);
							reject(`unable to get steam time offset`);
							return
						}
						steamTimeOffset = offset;
						callback(SteamTotp.getAuthCode(sharedSecret, steamTimeOffset));
					});
					return;
				}
				callback(SteamTotp.getAuthCode(sharedSecret, steamTimeOffset));
			} else if (!win) {
				currently_checking = currently_checking.filter(x => x !== username);
				reject(`steam guard missing`);
			} else {
				win.webContents.send('steam:steamguard', username);
				ipcMain.once('steam:steamguard:response', async (event, code) => {
					if (!code) {
						currently_checking = currently_checking.filter(x => x !== username);
						reject(`steam guard missing`);
					} else {
						callback(code);
					}
				});
			}
		});

		let data = {};

		steamClient.on('loggedOn', () => {
			console.log('Successfully logged into Steam!');
			console.log(`Logged in as: ${steamClient.steamID.getSteamID64()}`);

		});

		steamClient.on('accountInfo', (name, country, authedMachines, flags, facebookID, facebookName) => {
			data = Object.assign({}, data, { name, country, authedMachines, flags, facebookID, facebookName });
			console.log(name);
			steamClient.gamesPlayed([730]);
		});

		csClient.on('connectedToGC', () => {
			console.log('connected to gc');
			csClient.requestPlayersProfile(steamClient.steamID.getSteamID64())
		})

		csClient.on('playersProfile', playersProfile => {

			currently_checking = currently_checking.filter(x => x !== username);

			data = Object.assign({}, data, playersProfile);
			// find the Premier (matchmaking) ranking entry
			let premier = (playersProfile.rankings || [])
				.find(r => r.rank_type_id === 11);

			if (!premier) return resolve(data);

			let eloRanges = [
				[0, 4999],
				[5000, 9999],
				[10000, 14999],
				[15000, 19999],
				[20000, 24999],
				[25000, 29999],
				[30000, Infinity],
			];

			let eloIndex = eloRanges.findIndex(
				([min, max]) => premier.rank_id >= min && premier.rank_id <= max
			);

			premier = Object.assign(premier, { eloIndex });
			resolve(data);
		})



	});
}
