import { openDB, IDBPDatabase } from 'idb';

const DB_NAME = 'hyper_vault_db';
const DB_VERSION = 1;

const STORES = {
  SETTINGS: 'settings',
  PASSWORDS: 'passwords',
  NOTES: 'notes',
  WEBAUTHN: 'webauthn'
};

let dbPromise: Promise<IDBPDatabase> | null = null;

const getDB = () => {
  if (!dbPromise) {
    dbPromise = openDB(DB_NAME, DB_VERSION, {
      upgrade(db) {
        Object.values(STORES).forEach(storeName => {
          if (!db.objectStoreNames.contains(storeName)) {
            db.createObjectStore(storeName, { keyPath: 'id', autoIncrement: true });
          }
        });
        // Settings store doesn't need autoIncrement for simple key-value
        if (db.objectStoreNames.contains(STORES.SETTINGS)) {
          db.deleteObjectStore(STORES.SETTINGS);
        }
        db.createObjectStore(STORES.SETTINGS);
      },
    });
  }
  return dbPromise;
};

// Migration from localStorage to IndexedDB
const migrateFromLocalStorage = async () => {
  const migratedKey = 'hv_migrated_to_idb';
  if (localStorage.getItem(migratedKey)) return;

  const db = await getDB();

  // Migrate settings
  const settingsKeys = {
    'master_salt': 'hv_master_salt',
    'auth_salt': 'hv_auth_salt',
    'auth_hash': 'hv_auth_hash'
  };

  for (const [key, lsKey] of Object.entries(settingsKeys)) {
    const val = localStorage.getItem(lsKey);
    if (val) await db.put(STORES.SETTINGS, val, key);
  }

  // Migrate arrays
  const arrayKeys = {
    [STORES.PASSWORDS]: 'hv_passwords',
    [STORES.NOTES]: 'hv_notes',
    [STORES.WEBAUTHN]: 'hv_webauthn'
  };

  for (const [store, lsKey] of Object.entries(arrayKeys)) {
    const data = localStorage.getItem(lsKey);
    if (data) {
      const items = JSON.parse(data);
      const tx = db.transaction(store, 'readwrite');
      for (const item of items) {
        await tx.store.put(item);
      }
      await tx.done;
    }
  }

  localStorage.setItem(migratedKey, 'true');
};

// Initialize migration
migrateFromLocalStorage();

export const storage = {
  getSetting: async (key: string) => {
    const db = await getDB();
    return db.get(STORES.SETTINGS, key);
  },
  
  saveSetting: async (key: string, value: string) => {
    const db = await getDB();
    await db.put(STORES.SETTINGS, value, key);
  },

  getPasswords: async () => {
    const db = await getDB();
    return db.getAll(STORES.PASSWORDS);
  },

  savePassword: async (password: any) => {
    const db = await getDB();
    const newPassword = { ...password, created_at: new Date().toISOString() };
    const id = await db.add(STORES.PASSWORDS, newPassword);
    return { ...newPassword, id };
  },

  updatePassword: async (id: number, updatedData: any) => {
    const db = await getDB();
    const item = await db.get(STORES.PASSWORDS, Number(id));
    if (item) {
      await db.put(STORES.PASSWORDS, { ...item, ...updatedData, id: Number(id) });
    }
  },

  deletePassword: async (id: number) => {
    const db = await getDB();
    await db.delete(STORES.PASSWORDS, Number(id));
  },

  getNotes: async () => {
    const db = await getDB();
    return db.getAll(STORES.NOTES);
  },

  saveNote: async (note: any) => {
    const db = await getDB();
    const newNote = { ...note, created_at: new Date().toISOString() };
    const id = await db.add(STORES.NOTES, newNote);
    return { ...newNote, id };
  },

  deleteNote: async (id: number) => {
    const db = await getDB();
    await db.delete(STORES.NOTES, Number(id));
  },

  getWebAuthnCredentials: async () => {
    const db = await getDB();
    return db.getAll(STORES.WEBAUTHN);
  },

  saveWebAuthnCredential: async (credential: any) => {
    const db = await getDB();
    await db.add(STORES.WEBAUTHN, credential);
  }
};
